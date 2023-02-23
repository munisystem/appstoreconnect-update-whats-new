package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "appstoreconnect-update-whats-new",
	Short: "Update the Whats's New of an App Store Connect build",
	RunE:  run,
}

var (
	appID      string
	keyID      string
	issuer     string
	privateKey string
	version    string
)

func run(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("invalid number of arguments")
	}
	message := args[0]

	privateKey, err := readPrivateKey(privateKey)
	if err != nil {
		return err
	}

	token, err := generateAuthToken(privateKey, issuer, keyID)
	if err != nil {
		return err
	}

	client := newAppStoreConnectAPI(token)
	id, err := client.GetBuildID(appID, version)
	if err != nil {
		return err
	}

	if err := client.UpdateWhatsNew(id, message); err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.Flags().StringVar(&appID, "app-id", "", "App ID of the App Store Connect")
	rootCmd.Flags().StringVar(&keyID, "api-key-id", "", "API Key ID of the App Store Connect")
	rootCmd.Flags().StringVar(&issuer, "api-issuer", "", "API issuer ID of the App Store Connect")
	rootCmd.Flags().StringVar(&privateKey, "private-key", "", "API private key path of URL of the App Store Connect")
	rootCmd.Flags().StringVar(&version, "version", "", "Build version of the target")

	rootCmd.MarkFlagRequired("app-id")
	rootCmd.MarkFlagRequired("api-key-id")
	rootCmd.MarkFlagRequired("api-issuer")
	rootCmd.MarkFlagRequired("private-key")
	rootCmd.MarkFlagRequired("version")
}

func main() {
	rootCmd.Execute()
}

func readPrivateKey(keyPath string) (*ecdsa.PrivateKey, error) {
	var bytes []byte
	if strings.HasPrefix(string(keyPath), "https://") {
		client := &http.Client{}
		req, err := http.NewRequest("GET", keyPath, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to download App Store Connect API key: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to download App Store Connect API key: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to download App Store Connect API key: status code %d", resp.StatusCode)
		}
		defer resp.Body.Close()
		bytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read App Store Connect API key download response: %w", err)
		}
	} else {
		trimmedPath := keyPath
		if strings.HasPrefix(keyPath, "file://") {
			trimmedPath = strings.TrimPrefix(keyPath, "file://")
		}
		var err error
		bytes, err = os.ReadFile(trimmedPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("doesn't exists App Store Connect API at %s", trimmedPath)
		} else if err != nil {
			return nil, fmt.Errorf("failed to read App Store Connect API at %s: %w", trimmedPath, err)
		}
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("failed to decode .p8 file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pk := key.(type) {
	case *ecdsa.PrivateKey:
		return pk, nil
	default:
		return nil, errors.New("receive unexpected key type")
	}
}

func generateAuthToken(privateKey *ecdsa.PrivateKey, issuerID string, keyID string) (string, error) {
	expirationTimestamp := time.Now().Add(time.Minute * 10)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": issuerID,
		"exp": expirationTimestamp.Unix(),
		"aud": "appstoreconnect-v1",
	})
	token.Header["kid"] = keyID

	str, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return str, nil
}

type AppStoreConnectAPI struct {
	client *http.Client
	token  string
}

func newAppStoreConnectAPI(token string) *AppStoreConnectAPI {
	return &AppStoreConnectAPI{
		client: &http.Client{},
		token:  token,
	}
}

type ListBuildResponse struct {
	Data  []*Build    `json:"data"`
	Links interface{} `json:"-"`
	Meta  interface{} `json:"-"`
}

type Build struct {
	Type          string      `json:"-"`
	ID            string      `json:"id"`
	Attributes    interface{} `json:"-"`
	Relationships interface{} `json:"-"`
}

func (app *AppStoreConnectAPI) GetBuildID(appID, version string) (string, error) {
	queries := url.Values{}
	queries.Set("filter[app]", appID)
	queries.Set("filter[version]", version)

	req, err := http.NewRequest(
		http.MethodGet,
		"https://api.appstoreconnect.apple.com/v1/builds?"+queries.Encode(),
		nil,
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+app.token)

	resp, err := app.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	response := &ListBuildResponse{}
	if err := json.Unmarshal(bytes, response); err != nil {
		return "", err
	}

	if len(response.Data) == 0 {
		return "", errors.New("no build found")
	}

	return response.Data[0].ID, nil
}

type UpdateWhatsNewRequest struct {
	Data *UpdateWhatsNewRequestData `json:"data"`
}

type UpdateWhatsNewRequestData struct {
	Attributes *UpdateWhatsNewRequestAttributes `json:"attributes"`
	ID         string                           `json:"id"`
	Type       string                           `json:"type"`
}

type UpdateWhatsNewRequestAttributes struct {
	WhatsNew string `json:"whatsNew"`
}

func (app *AppStoreConnectAPI) UpdateWhatsNew(buildID, message string) error {
	betaBuildLocalizationID, err := app.getBetaBuildLocalizationID(buildID)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("https://api.appstoreconnect.apple.com/v1/betaBuildLocalizations/%s", betaBuildLocalizationID)
	body := &UpdateWhatsNewRequest{
		Data: &UpdateWhatsNewRequestData{
			Type: "betaBuildLocalizations",
			ID:   betaBuildLocalizationID,
			Attributes: &UpdateWhatsNewRequestAttributes{
				WhatsNew: message,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(
		http.MethodPatch,
		endpoint,
		bytes.NewBuffer(b),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+app.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to update what's new. response code: %d, response body: %s", resp.StatusCode, string(bytes))
	}

	return nil
}

type GetBetaBuildLocalizationsResponse struct {
	Data  []*GetBetaBuildLocalizationsResponseData `json:"data"`
	Links interface{}                              `json:"-"`
	Meta  interface{}                              `json:"-"`
}

type GetBetaBuildLocalizationsResponseData struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (app *AppStoreConnectAPI) getBetaBuildLocalizationID(buildID string) (string, error) {
	endpoint := fmt.Sprintf("https://api.appstoreconnect.apple.com/v1/builds/%s/relationships/betaBuildLocalizations", buildID)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+app.token)

	resp, err := app.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to get beta build localization id. response code: %d, response body: %s", resp.StatusCode, string(bytes))
	}

	response := &GetBetaBuildLocalizationsResponse{}
	if err := json.Unmarshal(bytes, response); err != nil {
		return "", err
	}

	if len(response.Data) == 0 {
		return "", errors.New("no build found")
	}

	return response.Data[0].ID, nil
}
