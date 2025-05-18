package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type AuthServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration              bool     `json:"require_request_uri_registration"`
	ScopesSupported                            []string `json:"scopes_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	UILocalesSupported                         []string `json:"ui_locales_supported"`
	DisplayValuesSupported                     []string `json:"display_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported"`
	JwksURI                                    string   `json:"jwks_uri"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint"`
	RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests"`
	DPoPSigningAlgValuesSupported              []string `json:"dpop_signing_alg_values_supported"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
}

func FetchAuthServerMetadata(endpoint string) (AuthServerMetadata, error) {
	c := http.Client{
		Timeout: time.Second * 60,
	}

	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/.well-known/oauth-authorization-server", endpoint),
		nil,
	)

	res, err := c.Do(req)
	if err != nil {
		return AuthServerMetadata{}, err
	}

	defer res.Body.Close()

	var data *AuthServerMetadata
	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		return AuthServerMetadata{}, err
	}

	return *data, nil
}

type PDSResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceDocumentation  string   `json:"resource_documentation"`
}

func FetchPDSResourceMetadata(endpoint string) (PDSResourceMetadata, error) {
	c := http.Client{
		Timeout: time.Second * 60,
	}

	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/.well-known/oauth-protected-resource", endpoint),
		nil,
	)

	res, err := c.Do(req)
	if err != nil {
		return PDSResourceMetadata{}, err
	}

	defer res.Body.Close()

	var data *PDSResourceMetadata
	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		return PDSResourceMetadata{}, err
	}

	return *data, nil
}
