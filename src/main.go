package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

var (
	version = "0.1.0" // Set via -ldflags at build time
)

const (
	testnetAPI = "https://api.grapevine.markets"
	mainnetAPI = "https://api.grapevine.fyi"
	keyringService = "grapevine-cli"
)

var (
	cfgFile            string
	network            string
	privateKey         string
	debug              bool
	cachedPrivateKey   string // Cache decrypted private key for session
	rootCmd    = &cobra.Command{
		Use:   "grapevine",
		Short: "CLI for the Grapevine API",
		Long:  `Command-line interface for the Grapevine API - Create and manage content feeds with x402 micropayments`,
	}
)

type Config struct {
	Network        string            `json:"network"`
	ActiveAccount  string            `json:"activeAccount,omitempty"`
	Accounts       map[string]string `json:"accounts,omitempty"` // alias -> address
	ConfiguredAt   time.Time         `json:"configuredAt"`
}

type GrapevineClient struct {
	apiURL     string
	privateKey *ecdsa.PrivateKey
	address    common.Address
	network    string
	isTestnet  bool
	debug      bool
}

type Feed struct {
	ID                 string   `json:"id"`
	OwnerID            string   `json:"owner_id"`
	OwnerWalletAddress string   `json:"owner_wallet_address"`
	CategoryID         string   `json:"category_id,omitempty"`
	Name               string   `json:"name"`
	Description        string   `json:"description,omitempty"`
	ImageURL           string   `json:"image_url,omitempty"`
	IsActive           bool     `json:"is_active"`
	TotalEntries       int      `json:"total_entries"`
	TotalPurchases     int      `json:"total_purchases"`
	TotalRevenue       string   `json:"total_revenue"`
	Tags               []string `json:"tags"`
	CreatedAt          int64    `json:"created_at"`
	UpdatedAt          int64    `json:"updated_at"`
}

type Entry struct {
	ID             string   `json:"id"`
	FeedID         string   `json:"feed_id"`
	CID            string   `json:"cid"`
	MimeType       string   `json:"mime_type"`
	Title          string   `json:"title,omitempty"`
	Description    string   `json:"description,omitempty"`
	Metadata       string   `json:"metadata,omitempty"`
	Tags           []string `json:"tags"`
	IsFree         bool     `json:"is_free"`
	ExpiresAt      int64    `json:"expires_at,omitempty"`
	IsActive       bool     `json:"is_active"`
	TotalPurchases int      `json:"total_purchases"`
	TotalRevenue   interface{} `json:"total_revenue"`
	CreatedAt      int64    `json:"created_at"`
	UpdatedAt      int64    `json:"updated_at"`
}

type Category struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type PaginatedResponse[T any] struct {
	Data          []T    `json:"data"`
	Feeds         []T    `json:"feeds,omitempty"` // Some endpoints use "feeds" instead of "data"
	Entries       []T    `json:"entries,omitempty"` // Some endpoints use "entries" 
	NextPageToken string `json:"next_page_token,omitempty"`
	TotalCount    int    `json:"total_count"`
}

type PaymentRequirement struct {
	Amount            string `json:"amount"`
	Currency          string `json:"currency"`
	RecipientAddress  string `json:"recipient_address"`
	ChainID          string `json:"chain_id"`
	ContractAddress  string `json:"contract_address"`
}

type PaymentResponse struct {
	PaymentRequired bool               `json:"payment_required"`
	PaymentInfo     PaymentRequirement `json:"payment_info"`
}

// X402 standard payment structures
type X402Accept struct {
	Scheme               string                 `json:"scheme"`
	Network              string                 `json:"network"`
	MaxAmountRequired    string                 `json:"maxAmountRequired"`
	Resource             string                 `json:"resource"`
	Description          string                 `json:"description"`
	MimeType             string                 `json:"mimeType"`
	PayTo                string                 `json:"payTo"`
	MaxTimeoutSeconds    int                    `json:"maxTimeoutSeconds"`
	Asset                string                 `json:"asset"`
	Extra                map[string]interface{} `json:"extra,omitempty"`
}

type X402Response struct {
	Error        string       `json:"error"`
	Accepts      []X402Accept `json:"accepts"`
	X402Version  int          `json:"x402Version"`
}

// X402 Payment Payload structures
type X402PaymentPayload struct {
	X402Version int         `json:"x402Version"`
	Scheme      string      `json:"scheme"`
	Network     string      `json:"network"`
	Payload     interface{} `json:"payload"`
}

// Exact payment scheme payload (Simple authorization)
type ExactPaymentPayload struct {
	Signature     string                 `json:"signature"`
	Authorization AuthorizationPayload   `json:"authorization"`
}

type AuthorizationPayload struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&network, "network", "n", "testnet", "Network to use (testnet/mainnet)")
	rootCmd.PersistentFlags().StringVarP(&privateKey, "key", "k", "", "Private key (or use PRIVATE_KEY env var)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug output")

	rootCmd.AddCommand(feedCmd)
	rootCmd.AddCommand(entryCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(categoriesCmd)
	rootCmd.AddCommand(walletCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		configDir := filepath.Join(home, ".grapevine")
		os.MkdirAll(configDir, 0755)

		viper.AddConfigPath(configDir)
		viper.SetConfigType("json")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv()
	viper.ReadInConfig()
}

// Account management helper functions
func getAccountAddress(privateKeyStr string) (string, error) {
	// Remove 0x prefix if present
	if strings.HasPrefix(privateKeyStr, "0x") {
		privateKeyStr = privateKeyStr[2:]
	}

	privateKey, err := crypto.HexToECDSA(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address.Hex(), nil
}

// Keyring helper functions
func storePrivateKey(alias, privateKey string) error {
	return keyring.Set(keyringService, alias, privateKey)
}

func getPrivateKey(alias string) (string, error) {
	return keyring.Get(keyringService, alias)
}

func deletePrivateKey(alias string) error {
	return keyring.Delete(keyringService, alias)
}

func getPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add newline after password input
	return string(password), err
}

func getConfigPath() (string, string) {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".grapevine")
	configFile := filepath.Join(configDir, "config.json")
	return configDir, configFile
}

func loadConfig() (*Config, error) {
	_, configFile := getConfigPath()
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	
	// Ensure Accounts map is always initialized for backward compatibility
	if config.Accounts == nil {
		config.Accounts = make(map[string]string)
	}
	
	return &config, nil
}

func saveConfig(config *Config) error {
	configDir, configFile := getConfigPath()
	if err := os.MkdirAll(configDir, 0700); err != nil { // 0700 for security
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFile, data, 0600) // 0600 for security
}

func getClient(requireAuth bool) (*GrapevineClient, error) {
	// Get private key from flag, env, or keyring
	key := privateKey
	if key == "" {
		key = os.Getenv("PRIVATE_KEY")
	}

	// If no key from flag/env and auth is required, get from keyring
	if key == "" && requireAuth {
		// Load config to find active account
		config, err := loadConfig()
		if err != nil {
			return nil, fmt.Errorf("no configuration found. Run 'grapevine auth login --alias <name>' to add an account")
		}

		if config.ActiveAccount == "" {
			return nil, fmt.Errorf("no active account set. Run 'grapevine auth login --alias <name>' to add an account")
		}

		// Get private key from keyring using active account alias
		key, err = getPrivateKey(config.ActiveAccount)
		if err != nil {
			return nil, fmt.Errorf("failed to get private key for account '%s': %v. Run 'grapevine auth login --alias %s' to re-add the account", config.ActiveAccount, err, config.ActiveAccount)
		}
	}

	if requireAuth && key == "" {
		return nil, fmt.Errorf("private key required. Use --key flag, set PRIVATE_KEY env var, or run 'grapevine auth login' to save encrypted key")
	}

	client := &GrapevineClient{
		network:   network,
		isTestnet: network != "mainnet",
		debug:     debug,
	}

	if network == "mainnet" {
		client.apiURL = mainnetAPI
	} else {
		client.apiURL = testnetAPI
	}

	if key != "" {
		if !strings.HasPrefix(key, "0x") {
			return nil, fmt.Errorf("private key must start with 0x")
		}
		if len(key) != 66 {
			return nil, fmt.Errorf("invalid private key length")
		}

		// Parse private key
		keyBytes, err := hexutil.Decode(key)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key: %v", err)
		}

		privKey, err := crypto.ToECDSA(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}

		client.privateKey = privKey
		client.address = crypto.PubkeyToAddress(privKey.PublicKey)
	}

	return client, nil
}

func (c *GrapevineClient) getChainID() string {
	if c.isTestnet {
		return "84532" // base-sepolia
	}
	return "8453" // base mainnet
}

func (c *GrapevineClient) getUSDCContractAddress() string {
	if c.isTestnet {
		return "0x036CbD53842c5426634e7929541eC2318f3dCF7e" // USDC on base-sepolia
	}
	return "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" // USDC on base mainnet
}

func (c *GrapevineClient) getChainIDFromNetwork(network string) string {
	switch strings.ToLower(network) {
	case "base-sepolia":
		return "84532"
	case "base":
		return "8453"
	default:
		// Default to testnet
		return "84532"
	}
}

func (c *GrapevineClient) createX402PaymentHeader(accept X402Accept, x402Version int) (string, error) {
	if c.privateKey == nil {
		return "", fmt.Errorf("private key required for payment")
	}

	if accept.Scheme != "exact" {
		return "", fmt.Errorf("unsupported payment scheme: %s", accept.Scheme)
	}

	// Generate 32-byte nonce like TypeScript SDK (crypto.getRandomValues(new Uint8Array(32)))
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}
	nonce := fmt.Sprintf("0x%x", nonceBytes) // This creates 0x + 64 hex chars
	
	// Create authorization parameters (matching TypeScript SDK timing)
	now := time.Now()
	authorization := AuthorizationPayload{
		From:        c.address.Hex(),
		To:          accept.PayTo,
		Value:       accept.MaxAmountRequired,
		ValidAfter:  fmt.Sprintf("%d", now.Unix()-600), // 10 minutes before, like SDK
		ValidBefore: fmt.Sprintf("%d", now.Unix()+int64(accept.MaxTimeoutSeconds)),
		Nonce:       nonce,
	}

	if c.debug {
		fmt.Printf("Creating EIP-712 authorization:\n")
		fmt.Printf("  From: %s\n", authorization.From)
		fmt.Printf("  To: %s\n", authorization.To)
		fmt.Printf("  Value: %s\n", authorization.Value)
		fmt.Printf("  ValidAfter: %s\n", authorization.ValidAfter)
		fmt.Printf("  ValidBefore: %s\n", authorization.ValidBefore)
		fmt.Printf("  Nonce: %s (length: %d)\n", authorization.Nonce, len(authorization.Nonce))
	}

	// Create EIP-712 typed data signature like TypeScript SDK
	signature, err := c.signEIP712Authorization(authorization, accept)
	if err != nil {
		return "", fmt.Errorf("failed to sign EIP-712 authorization: %v", err)
	}
	
	signatureHex := hexutil.Encode(signature)

	if c.debug {
		fmt.Printf("  Signature: %s\n", signatureHex)
	}

	// Create the x402 payment payload
	exactPayload := ExactPaymentPayload{
		Signature:     signatureHex,
		Authorization: authorization,
	}

	payload := X402PaymentPayload{
		X402Version: x402Version,
		Scheme:      accept.Scheme,
		Network:     accept.Network,
		Payload:     exactPayload,
	}

	// Encode to JSON then base64
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payment payload: %v", err)
	}

	paymentHeader := base64.StdEncoding.EncodeToString(payloadJSON)

	if c.debug {
		fmt.Printf("  X-PAYMENT header payload: %s\n", string(payloadJSON))
	}

	return paymentHeader, nil
}

func (c *GrapevineClient) signEIP712Authorization(auth AuthorizationPayload, accept X402Accept) ([]byte, error) {
	// Get network chain ID
	chainID, err := strconv.ParseInt(c.getChainIDFromNetwork(accept.Network), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid chain ID: %v", err)
	}

	// EIP-712 domain parameters (from x402 TypeScript SDK)
	// Use values from accept.Extra if available, fallback to defaults
	name := "USD Coin"
	version := "2"
	if accept.Extra != nil {
		if extraName, ok := accept.Extra["name"].(string); ok {
			name = extraName
		}
		if extraVersion, ok := accept.Extra["version"].(string); ok {
			version = extraVersion
		}
	}

	// Create proper TypedData structure using go-ethereum's apitypes
	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"TransferWithAuthorization": []apitypes.Type{
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"},
				{Name: "nonce", Type: "bytes32"},
			},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{
			Name:              name,
			Version:           version,
			ChainId:           (*math.HexOrDecimal256)(big.NewInt(chainID)),
			VerifyingContract: accept.Asset,
		},
		Message: apitypes.TypedDataMessage{
			"from":        auth.From,
			"to":          auth.To,
			"value":       auth.Value,
			"validAfter":  auth.ValidAfter,
			"validBefore": auth.ValidBefore,
			"nonce":       auth.Nonce,
		},
	}

	// Use go-ethereum's standard EIP-712 hash computation 
	hash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return nil, fmt.Errorf("failed to hash typed data: %v", err)
	}

	// Sign the hash using standard crypto.Sign
	signature, err := crypto.Sign(hash, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %v", err)
	}

	// Ethereum signature format (v = recovery + 27)
	signature[64] += 27

	return signature, nil
}


func (c *GrapevineClient) getAuthHeaders() (map[string]string, error) {
	if c.privateKey == nil {
		return nil, fmt.Errorf("authentication not configured")
	}

	// Step 1: Request nonce from API
	nonceURL := c.apiURL + "/v1/auth/nonce"
	nonceBody := map[string]string{
		"wallet_address": c.address.Hex(),
	}
	
	jsonBody, err := json.Marshal(nonceBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal nonce request: %v", err)
	}

	if c.debug {
		fmt.Printf("Requesting nonce from: %s\n", nonceURL)
	}

	resp, err := http.Post(nonceURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to request nonce: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nonce request failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var nonceResp struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
		return nil, fmt.Errorf("failed to decode nonce response: %v", err)
	}

	// Step 2: Sign the nonce message using go-ethereum's standard personal message signing
	// This uses the same approach as payments: proper library function
	message := nonceResp.Message
	hash := accounts.TextHash([]byte(message))
	
	signature, err := crypto.Sign(hash, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign nonce message: %v", err)
	}

	// Standard Ethereum signature format (same as payments)
	signature[64] += 27

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	chainID := c.getChainID()

	if c.debug {
		fmt.Printf("Auth signature debug:\n")
		fmt.Printf("  Message: %s\n", nonceResp.Message)
		fmt.Printf("  Message length: %d\n", len(message))
		fmt.Printf("  Hash: %s\n", hexutil.Encode(hash))
		fmt.Printf("  Signature: %s\n", hexutil.Encode(signature))
		fmt.Printf("  Recovery byte: %d\n", signature[64])
		fmt.Printf("  Wallet: %s\n", c.address.Hex())
		fmt.Printf("  Timestamp: %s\n", timestamp)
		fmt.Printf("  Chain ID: %s\n", chainID)
	}

	return map[string]string{
		"x-wallet-address": c.address.Hex(),
		"x-signature":      hexutil.Encode(signature),
		"x-message":        nonceResp.Message,
		"x-timestamp":      timestamp,
		"x-chain-id":       chainID,
	}, nil
}

func (c *GrapevineClient) request(method, path string, body interface{}, requireAuth bool) (*http.Response, error) {
	return c.requestWithPayment(method, path, body, requireAuth, "", nil)
}

func (c *GrapevineClient) requestWithPayment(method, path string, body interface{}, requireAuth bool, paymentTx string, originalAuthHeaders map[string]string) (*http.Response, error) {
	url := c.apiURL + path

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Use provided auth headers (for retry) or generate new ones
	var authHeaders map[string]string
	if originalAuthHeaders != nil {
		authHeaders = originalAuthHeaders
	} else if requireAuth {
		authHeaders, err = c.getAuthHeaders()
		if err != nil {
			return nil, err
		}
	}

	// Set auth headers
	for k, v := range authHeaders {
		req.Header.Set(k, v)
	}

	// Add payment header if provided
	if paymentTx != "" {
		req.Header.Set("x-payment", paymentTx)
		req.Header.Set("Access-Control-Expose-Headers", "X-PAYMENT-RESPONSE")
	}

	if c.debug {
		fmt.Printf("Request: %s %s\n", method, url)
		if paymentTx != "" {
			fmt.Printf("Payment TX: %s\n", paymentTx[:20]+"...")
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle 402 Payment Required
	if resp.StatusCode == 402 && paymentTx == "" {
		defer resp.Body.Close()
		
		// Parse payment requirements from response body
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read payment response: %v", err)
		}

		if c.debug {
			fmt.Printf("402 Response body: %s\n", string(bodyBytes))
		}

		// Parse X402 response
		var x402Resp X402Response
		if err := json.Unmarshal(bodyBytes, &x402Resp); err != nil {
			return nil, fmt.Errorf("failed to parse X402 response: %v\nResponse: %s", err, string(bodyBytes))
		}

		if len(x402Resp.Accepts) == 0 {
			return nil, fmt.Errorf("no payment methods available")
		}

		// Use the first available payment method
		accept := x402Resp.Accepts[0]
		
		fmt.Printf("Payment required: %s microUSDC to %s\n", 
			accept.MaxAmountRequired,
			accept.PayTo)

		// Create x402 payment header
		paymentHeader, err := c.createX402PaymentHeader(accept, x402Resp.X402Version)
		if err != nil {
			return nil, fmt.Errorf("failed to create payment header: %v", err)
		}

		fmt.Println("X402 payment header created, retrying request...")

		// Retry the request with payment using fresh auth headers (payment may take time)
		return c.requestWithPayment(method, path, body, requireAuth, paymentHeader, nil)
	}

	if c.debug && resp.Header.Get("X-PAYMENT-RESPONSE") != "" {
		fmt.Println("Payment processed successfully")
	}

	return resp, nil
}

var feedCmd = &cobra.Command{
	Use:   "feed",
	Short: "Feed operations",
}

var feedCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new feed",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		description, _ := cmd.Flags().GetString("description")
		tagsStr, _ := cmd.Flags().GetString("tags")
		
		tags := []string{} // Initialize as empty array, not nil
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
		}

		body := map[string]interface{}{
			"name":        args[0],
			"description": description,
			"tags":        tags,
		}

		fmt.Println("Creating feed...")
		resp, err := client.request("POST", "/v1/feeds", body, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to create feed: %s", string(bodyBytes))
		}

		var feed Feed
		if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
			return err
		}

		fmt.Printf("✅ Feed created: %s\n", feed.ID)
		fmt.Printf("   View at: https://grapevine.markets/feeds/%s/entries\n", feed.ID)
		return nil
	},
}

var feedListCmd = &cobra.Command{
	Use:   "list",
	Short: "List feeds",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		owner, _ := cmd.Flags().GetString("owner")
		tagsStr, _ := cmd.Flags().GetString("tags")
		active, _ := cmd.Flags().GetBool("active")
		limit, _ := cmd.Flags().GetInt("limit")
		category, _ := cmd.Flags().GetString("category")
		minEntries, _ := cmd.Flags().GetInt("min-entries")
		minAge, _ := cmd.Flags().GetInt("min-age")
		maxAge, _ := cmd.Flags().GetInt("max-age")
		pageToken, _ := cmd.Flags().GetString("page")

		query := "?page_size=" + strconv.Itoa(limit)
		if owner != "" {
			query += "&owner_wallet_address=" + owner
		}
		if tagsStr != "" {
			tags := strings.Split(tagsStr, ",")
			for _, tag := range tags {
				query += "&tags=" + strings.TrimSpace(tag)
			}
		}
		if active {
			query += "&is_active=true"
		}
		if category != "" {
			query += "&category=" + category
		}
		if minEntries > 0 {
			query += "&min_entries=" + strconv.Itoa(minEntries)
		}
		if minAge > 0 {
			query += "&min_age=" + strconv.Itoa(minAge)
		}
		if maxAge > 0 {
			query += "&max_age=" + strconv.Itoa(maxAge)
		}
		if pageToken != "" {
			query += "&page_token=" + pageToken
		}

		resp, err := client.request("GET", "/v1/feeds"+query, nil, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to list feeds: %s", string(bodyBytes))
		}

		var result PaginatedResponse[Feed]
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		// Handle different response formats
		feeds := result.Data
		if len(feeds) == 0 && len(result.Feeds) > 0 {
			feeds = result.Feeds
		}
		
		fmt.Printf("Found %d feeds:\n\n", result.TotalCount)
		for _, feed := range feeds {
			fmt.Printf("  📁 %s (%s)\n", feed.Name, feed.ID)
			fmt.Printf("     Entries: %d, Active: %v\n", feed.TotalEntries, feed.IsActive)
			if len(feed.Tags) > 0 {
				fmt.Printf("     Tags: %s\n", strings.Join(feed.Tags, ", "))
			}
			fmt.Println()
		}
		
		// Show pagination info
		if result.NextPageToken != "" {
			fmt.Printf("\n📌 Next page token: %s\n", result.NextPageToken)
			fmt.Printf("   Use --page \"%s\" to see next page\n", result.NextPageToken)
		}
		
		return nil
	},
}

var feedUpdateCmd = &cobra.Command{
	Use:   "update [id]",
	Short: "Update feed details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		name, _ := cmd.Flags().GetString("name")
		description, _ := cmd.Flags().GetString("description")
		tagsStr, _ := cmd.Flags().GetString("tags")
		active, _ := cmd.Flags().GetBool("active")
		inactive, _ := cmd.Flags().GetBool("inactive")
		categoryID, _ := cmd.Flags().GetString("category")
		imageURL, _ := cmd.Flags().GetString("image")

		// Build update body with only provided fields
		body := make(map[string]interface{})
		
		if name != "" {
			body["name"] = name
		}
		if description != "" {
			body["description"] = description
		}
		if tagsStr != "" {
			tags := strings.Split(tagsStr, ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
			body["tags"] = tags
		}
		if active {
			body["is_active"] = true
		}
		if inactive {
			body["is_active"] = false
		}
		if categoryID != "" {
			body["category_id"] = categoryID
		}
		if imageURL != "" {
			body["image_url"] = imageURL
		}

		if len(body) == 0 {
			return fmt.Errorf("no update fields provided")
		}

		resp, err := client.request("PATCH", "/v1/feeds/"+args[0], body, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to update feed: %s", string(bodyBytes))
		}

		var feed Feed
		if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
			return err
		}

		fmt.Printf("✅ Feed updated: %s\n", feed.ID)
		fmt.Printf("   Name: %s\n", feed.Name)
		fmt.Printf("   Active: %v\n", feed.IsActive)
		return nil
	},
}

var feedGetCmd = &cobra.Command{
	Use:   "get [id]",
	Short: "Get feed details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		resp, err := client.request("GET", "/v1/feeds/"+args[0], nil, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to get feed: %s", string(bodyBytes))
		}

		var feed Feed
		if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
			return err
		}

		fmt.Println("\n📁 Feed Details:")
		fmt.Printf("   Name: %s\n", feed.Name)
		fmt.Printf("   ID: %s\n", feed.ID)
		if feed.Description != "" {
			fmt.Printf("   Description: %s\n", feed.Description)
		} else {
			fmt.Println("   Description: None")
		}
		fmt.Printf("   Owner: %s\n", feed.OwnerWalletAddress)
		fmt.Printf("   Entries: %d\n", feed.TotalEntries)
		fmt.Printf("   Active: %v\n", feed.IsActive)
		if len(feed.Tags) > 0 {
			fmt.Printf("   Tags: %s\n", strings.Join(feed.Tags, ", "))
		} else {
			fmt.Println("   Tags: None")
		}
		fmt.Printf("   URL: https://grapevine.markets/feeds/%s/entries\n", feed.ID)
		return nil
	},
}

var feedDeleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a feed",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		// Confirm deletion
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			fmt.Printf("⚠️  Are you sure you want to delete feed %s? (y/N): ", args[0])
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("Deletion cancelled")
				return nil
			}
		}

		resp, err := client.request("DELETE", "/v1/feeds/"+args[0], nil, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to delete feed: %s", string(bodyBytes))
		}

		fmt.Printf("✅ Feed deleted: %s\n", args[0])
		return nil
	},
}

var feedMyFeedsCmd = &cobra.Command{
	Use:   "myfeeds",
	Short: "List feeds owned by authenticated wallet",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		limit, _ := cmd.Flags().GetInt("limit")

		// Use the authenticated wallet address
		query := "?page_size=" + strconv.Itoa(limit) + "&owner_wallet_address=" + client.address.Hex()

		resp, err := client.request("GET", "/v1/feeds"+query, nil, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to list feeds: %s", string(bodyBytes))
		}

		var result PaginatedResponse[Feed]
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		fmt.Printf("\n📁 My Feeds (%d):\n\n", result.TotalCount)
		for _, feed := range result.Data {
			fmt.Printf("  📁 %s (%s)\n", feed.Name, feed.ID)
			fmt.Printf("     Entries: %d, Active: %v\n", feed.TotalEntries, feed.IsActive)
			if feed.TotalRevenue != "" {
				fmt.Printf("     Revenue: %v\n", feed.TotalRevenue)
			}
			if len(feed.Tags) > 0 {
				fmt.Printf("     Tags: %s\n", strings.Join(feed.Tags, ", "))
			}
			fmt.Println()
		}
		return nil
	},
}

var entryCmd = &cobra.Command{
	Use:   "entry",
	Short: "Entry operations",
}

var entryAddCmd = &cobra.Command{
	Use:   "add [feedId] [content]",
	Short: "Add an entry to a feed",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		title, _ := cmd.Flags().GetString("title")
		description, _ := cmd.Flags().GetString("description")
		mimeType, _ := cmd.Flags().GetString("mime")
		isFile, _ := cmd.Flags().GetBool("file")
		isPaid, _ := cmd.Flags().GetBool("paid")
		price, _ := cmd.Flags().GetString("price")
		tagsStr, _ := cmd.Flags().GetString("tags")
		metadataStr, _ := cmd.Flags().GetString("metadata")
		expiresIn, _ := cmd.Flags().GetInt("expires")

		content := args[1]
		if isFile {
			data, err := os.ReadFile(content)
			if err != nil {
				return fmt.Errorf("failed to read file: %v", err)
			}
			content = string(data)
		}

		// Auto-detect MIME type if not provided (like SDK)
		if mimeType == "" {
			if strings.HasPrefix(content, "<svg") {
				mimeType = "image/svg+xml"
			} else if strings.HasPrefix(content, "<") {
				mimeType = "text/html"
			} else if strings.HasPrefix(content, "#") {
				mimeType = "text/markdown"
			} else {
				mimeType = "text/plain"
			}
		}

		// Convert content to base64 (like SDK)
		contentBase64 := base64.StdEncoding.EncodeToString([]byte(content))

		tags := []string{} // Initialize as empty array, not nil
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
		}

		// Build entry data like SDK
		body := map[string]interface{}{
			"content_base64": contentBase64,
			"mime_type":      mimeType,
			"title":          title,
			"is_free":        !isPaid, // default to free
			"tags":           tags,
		}

		if description != "" {
			body["description"] = description
		}

		// Add metadata if provided
		if metadataStr != "" {
			// Parse metadata as JSON
			var metadata map[string]interface{}
			if err := json.Unmarshal([]byte(metadataStr), &metadata); err != nil {
				// If not valid JSON, treat as string
				body["metadata"] = metadataStr
			} else {
				body["metadata"] = metadata
			}
		}

		// Add expiration if provided (hours from now)
		if expiresIn > 0 {
			expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Hour).Unix()
			body["expires_at"] = expiresAt
		}

		if isPaid {
			// Map CLI network to API network format
			apiNetwork := "base-sepolia"
			if client.network == "mainnet" {
				apiNetwork = "base"
			}
			
			body["price"] = map[string]interface{}{
				"amount":   price,
				"currency": "USDC",
				"network":  apiNetwork,
			}
		}

		fmt.Println("Creating entry...")
		resp, err := client.request("POST", "/v1/feeds/"+args[0]+"/entries", body, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to create entry: %s", string(bodyBytes))
		}

		var entry Entry
		if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
			return err
		}

		fmt.Printf("✅ Entry created: %s\n", entry.ID)
		fmt.Printf("   CID: %s\n", entry.CID)
		if entry.IsFree {
			fmt.Println("   Type: FREE")
		} else {
			fmt.Println("   Type: PAID")
		}
		return nil
	},
}

var entryGetCmd = &cobra.Command{
	Use:   "get [feedId] [entryId]",
	Short: "Get entry details",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(false) // No auth required for get
		if err != nil {
			return err
		}

		resp, err := client.request("GET", "/v1/feeds/"+args[0]+"/entries/"+args[1], nil, false)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to get entry: %s", string(bodyBytes))
		}

		var entry Entry
		if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
			return err
		}

		fmt.Println("\n📄 Entry Details:")
		fmt.Printf("   ID: %s\n", entry.ID)
		if entry.Title != "" {
			fmt.Printf("   Title: %s\n", entry.Title)
		}
		if entry.Description != "" {
			fmt.Printf("   Description: %s\n", entry.Description)
		}
		fmt.Printf("   Feed ID: %s\n", entry.FeedID)
		fmt.Printf("   CID: %s\n", entry.CID)
		fmt.Printf("   MIME Type: %s\n", entry.MimeType)
		fmt.Printf("   Type: %s\n", map[bool]string{true: "FREE", false: "PAID"}[entry.IsFree])
		fmt.Printf("   Active: %v\n", entry.IsActive)
		if len(entry.Tags) > 0 {
			fmt.Printf("   Tags: %s\n", strings.Join(entry.Tags, ", "))
		}
		if entry.Metadata != "" {
			fmt.Printf("   Metadata: %s\n", entry.Metadata)
		}
		if entry.ExpiresAt > 0 {
			fmt.Printf("   Expires: %s\n", time.Unix(entry.ExpiresAt, 0).Format(time.RFC3339))
		}
		fmt.Printf("   Purchases: %d\n", entry.TotalPurchases)
		if entry.TotalRevenue != nil {
			fmt.Printf("   Revenue: %v\n", entry.TotalRevenue)
		}
		fmt.Printf("   Created: %s\n", time.Unix(entry.CreatedAt, 0).Format(time.RFC3339))
		return nil
	},
}

var entryDeleteCmd = &cobra.Command{
	Use:   "delete [feedId] [entryId]",
	Short: "Delete an entry",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		// Confirm deletion
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			fmt.Printf("⚠️  Are you sure you want to delete entry %s? (y/N): ", args[1])
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("Deletion cancelled")
				return nil
			}
		}

		resp, err := client.request("DELETE", "/v1/feeds/"+args[0]+"/entries/"+args[1], nil, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to delete entry: %s", string(bodyBytes))
		}

		fmt.Printf("✅ Entry deleted: %s\n", args[1])
		return nil
	},
}

var entryBatchCmd = &cobra.Command{
	Use:   "batch [feedId] [jsonFile]",
	Short: "Batch create entries from JSON file",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		delayMs, _ := cmd.Flags().GetInt("delay")
		stopOnError, _ := cmd.Flags().GetBool("stop-on-error")

		// Read and parse the JSON file
		data, err := os.ReadFile(args[1])
		if err != nil {
			return fmt.Errorf("failed to read file: %v", err)
		}

		var entries []map[string]interface{}
		if err := json.Unmarshal(data, &entries); err != nil {
			return fmt.Errorf("failed to parse JSON: %v", err)
		}

		fmt.Printf("Starting batch creation of %d entries...\n\n", len(entries))
		
		successful := 0
		failed := 0
		
		for i, entryData := range entries {
			fmt.Printf("[%d/%d] Creating entry", i+1, len(entries))
			if title, ok := entryData["title"].(string); ok && title != "" {
				fmt.Printf(": %s", title)
			}
			fmt.Printf("...\n")

			// Build entry request body similar to entryAddCmd
			body := make(map[string]interface{})
			
			// Handle content encoding
			if content, ok := entryData["content"].(string); ok {
				contentBase64 := base64.StdEncoding.EncodeToString([]byte(content))
				body["content_base64"] = contentBase64
			} else {
				fmt.Printf("   ❌ Error: content field is required\n")
				failed++
				if stopOnError {
					return fmt.Errorf("stopped on error at entry %d", i+1)
				}
				continue
			}

			// Set defaults and copy fields
			body["is_free"] = true
			body["tags"] = []string{}
			if title, ok := entryData["title"].(string); ok {
				body["title"] = title
			}
			if desc, ok := entryData["description"].(string); ok {
				body["description"] = desc
			}
			if mimeType, ok := entryData["mime_type"].(string); ok {
				body["mime_type"] = mimeType
			} else {
				// Auto-detect MIME type
				if content, ok := entryData["content"].(string); ok {
					if strings.HasPrefix(content, "<svg") {
						body["mime_type"] = "image/svg+xml"
					} else if strings.HasPrefix(content, "<") {
						body["mime_type"] = "text/html"
					} else if strings.HasPrefix(content, "#") {
						body["mime_type"] = "text/markdown"
					} else {
						body["mime_type"] = "text/plain"
					}
				}
			}
			if tags, ok := entryData["tags"].([]interface{}); ok {
				stringTags := make([]string, len(tags))
				for j, tag := range tags {
					if str, ok := tag.(string); ok {
						stringTags[j] = str
					}
				}
				body["tags"] = stringTags
			}
			if isFree, ok := entryData["is_free"].(bool); ok {
				body["is_free"] = isFree
			}

			// Make the request
			resp, err := client.request("POST", "/v1/feeds/"+args[0]+"/entries", body, true)
			if err != nil {
				fmt.Printf("   ❌ Error: %v\n", err)
				failed++
				if stopOnError {
					return fmt.Errorf("stopped on error at entry %d", i+1)
				}
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				bodyBytes, _ := io.ReadAll(resp.Body)
				fmt.Printf("   ❌ Error: %s\n", string(bodyBytes))
				failed++
				if stopOnError {
					return fmt.Errorf("stopped on error at entry %d", i+1)
				}
				continue
			}

			var entry Entry
			if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
				fmt.Printf("   ❌ Error decoding response: %v\n", err)
				failed++
				if stopOnError {
					return fmt.Errorf("stopped on error at entry %d", i+1)
				}
				continue
			}

			fmt.Printf("   ✅ Created: %s\n", entry.ID)
			successful++

			// Rate limiting delay
			if delayMs > 0 && i < len(entries)-1 {
				time.Sleep(time.Duration(delayMs) * time.Millisecond)
			}
		}

		fmt.Printf("\n📊 Batch Results:\n")
		fmt.Printf("   ✅ Successful: %d\n", successful)
		fmt.Printf("   ❌ Failed: %d\n", failed)
		fmt.Printf("   📈 Success Rate: %.1f%%\n", float64(successful)*100/float64(len(entries)))
		
		return nil
	},
}

var entryListCmd = &cobra.Command{
	Use:   "list [feedId]",
	Short: "List entries in a feed",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		free, _ := cmd.Flags().GetBool("free")
		paid, _ := cmd.Flags().GetBool("paid")
		limit, _ := cmd.Flags().GetInt("limit")
		active, _ := cmd.Flags().GetBool("active")
		tagsStr, _ := cmd.Flags().GetString("tags")
		pageToken, _ := cmd.Flags().GetString("page")

		query := "?page_size=" + strconv.Itoa(limit)
		if free {
			query += "&is_free=true"
		} else if paid {
			query += "&is_free=false"
		}
		if active {
			query += "&is_active=true"
		}
		if tagsStr != "" {
			tags := strings.Split(tagsStr, ",")
			for _, tag := range tags {
				query += "&tags=" + strings.TrimSpace(tag)
			}
		}
		if pageToken != "" {
			query += "&page_token=" + pageToken
		}

		resp, err := client.request("GET", "/v1/feeds/"+args[0]+"/entries"+query, nil, true)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to list entries: %s", string(bodyBytes))
		}

		var result PaginatedResponse[Entry]
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		// Handle different response formats
		entries := result.Data
		if len(entries) == 0 && len(result.Entries) > 0 {
			entries = result.Entries
		}
		
		fmt.Printf("\nFound %d entries:\n\n", result.TotalCount)
		for _, entry := range entries {
			title := entry.Title
			if title == "" {
				title = "Untitled"
			}
			fmt.Printf("  📄 %s (%s)\n", title, entry.ID)
			typeStr := "FREE"
			if !entry.IsFree {
				typeStr = "PAID"
			}
			fmt.Printf("     Type: %s, %s\n", entry.MimeType, typeStr)
			fmt.Printf("     CID: %s\n", entry.CID)
			if len(entry.Tags) > 0 {
				fmt.Printf("     Tags: %s\n", strings.Join(entry.Tags, ", "))
			}
			fmt.Println()
		}
		
		// Show pagination info
		if result.NextPageToken != "" {
			fmt.Printf("\n📌 Next page token: %s\n", result.NextPageToken)
			fmt.Printf("   Use --page \"%s\" to see next page\n", result.NextPageToken)
		}
		
		return nil
	},
}

var categoriesCmd = &cobra.Command{
	Use:   "categories",
	Short: "List available categories",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(false)
		if err != nil {
			return err
		}

		resp, err := client.request("GET", "/v1/categories", nil, false)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to get categories: %s", string(bodyBytes))
		}

		var result PaginatedResponse[Category]
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		fmt.Println("\n📚 Available Categories:")
		for _, cat := range result.Data {
			fmt.Printf("  • %s\n", cat.Name)
			if cat.Description != "" {
				fmt.Printf("    %s\n", cat.Description)
			}
		}
		return nil
	},
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication management",
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Add account with private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		key, _ := cmd.Flags().GetString("key")
		alias, _ := cmd.Flags().GetString("alias")
		
		if key == "" {
			key = privateKey
		}
		if key == "" {
			key = os.Getenv("PRIVATE_KEY")
		}

		if key == "" {
			return fmt.Errorf("private key required. Use --key flag\n\n⚠️  Security Note:\n   Never share your private key with anyone.\n   Consider using environment variables for production.")
		}

		if !strings.HasPrefix(key, "0x") || len(key) != 66 {
			return fmt.Errorf("invalid private key format. Must be 66 characters starting with 0x")
		}

		// Test the key
		keyBytes, err := hexutil.Decode(key)
		if err != nil {
			return fmt.Errorf("failed to decode private key: %v", err)
		}

		privKey, err := crypto.ToECDSA(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}

		address := crypto.PubkeyToAddress(privKey.PublicKey)

		// Load or create config
		config, err := loadConfig()
		if err != nil {
			// Create new config
			config = &Config{
				Network:       network,
				Accounts:      make(map[string]string),
				ConfiguredAt:  time.Now(),
			}
		}
		
		// Ensure Accounts map is initialized (defensive programming)
		if config.Accounts == nil {
			config.Accounts = make(map[string]string)
		}
		
		// Use provided alias or default
		if alias == "" {
			alias = "default"
		}

		// Check if alias already exists
		if _, exists := config.Accounts[alias]; exists {
			fmt.Printf("⚠️  Account '%s' already exists. Do you want to overwrite it? (y/N): ", alias)
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("Operation cancelled")
				return nil
			}
		}

		config.Accounts[alias] = address.Hex()
		config.ActiveAccount = alias
		config.ConfiguredAt = time.Now()

		// Store private key in keyring
		err = storePrivateKey(alias, key)
		if err != nil {
			return fmt.Errorf("failed to store private key in keyring: %v", err)
		}

		if err := saveConfig(config); err != nil {
			return fmt.Errorf("failed to save config: %v", err)
		}

		_, configFile := getConfigPath()
		fmt.Println("\n✅ Account added successfully!")
		fmt.Printf("   Alias: %s\n", alias)
		fmt.Printf("   Wallet: %s\n", address.Hex())
		fmt.Printf("   Network: %s\n", network)
		fmt.Printf("   Config saved to: %s\n", configFile)
		fmt.Printf("\n🔐 Private key securely stored in system keyring\n")
		fmt.Printf("💡 Use 'grapevine auth list' to see all accounts\n")
		return nil
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication status",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("\n🔐 Authentication Status")

		config, err := loadConfig()
		if err != nil {
			fmt.Println("   ❌ No saved configuration found")
			fmt.Println("   Run 'grapevine auth login' to configure")
		} else {
			fmt.Println("   ✅ Configuration found")
			if config.ActiveAccount != "" {
				if address, exists := config.Accounts[config.ActiveAccount]; exists {
					fmt.Printf("   Active Account: %s (%s)\n", config.ActiveAccount, address)
				}
			}
			fmt.Printf("   Network: %s\n", config.Network)
			fmt.Printf("   Configured: %s\n", config.ConfiguredAt.Format(time.RFC3339))
			
			// Check if we have accounts in keyring
			if len(config.Accounts) > 0 {
				fmt.Printf("   🔐 %d account(s) in keyring\n", len(config.Accounts))
			}
		}

		fmt.Println("\n   Private Key Status:")
		key := privateKey
		if key == "" {
			key = os.Getenv("PRIVATE_KEY")
		}

		if key != "" && strings.HasPrefix(key, "0x") && len(key) == 66 {
			source := "PRIVATE_KEY env var"
			if privateKey != "" {
				source = "--key flag"
			}
			fmt.Printf("   ✅ Private key available (via %s)\n", source)
			
			if keyBytes, err := hexutil.Decode(key); err == nil {
				if privKey, err := crypto.ToECDSA(keyBytes); err == nil {
					address := crypto.PubkeyToAddress(privKey.PublicKey)
					fmt.Printf("   Wallet: %s\n", address.Hex())
				} else {
					fmt.Println("   ❌ Invalid private key")
				}
			}
		} else if config != nil && config.ActiveAccount != "" {
			fmt.Println("   🔐 Private key available (from keyring) - seamless authentication")
		} else {
			fmt.Println("   ❌ No private key available")
			fmt.Println("   Use --key flag, PRIVATE_KEY env var, or run 'grapevine auth login --save'")
		}
		return nil
	},
}

var authListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := loadConfig()
		if err != nil {
			fmt.Println("\n⚠️  No configuration found")
			fmt.Println("   Run 'grapevine auth login --alias <name>' to add an account")
			return nil
		}

		// Ensure Accounts map is initialized
		if config.Accounts == nil {
			config.Accounts = make(map[string]string)
		}

		if len(config.Accounts) == 0 {
			fmt.Println("\n⚠️  No accounts found")
			fmt.Println("   Run 'grapevine auth login --alias <name>' to add an account")
			return nil
		}

		fmt.Println("\n🔐 Saved Accounts:")
		for alias, address := range config.Accounts {
			status := ""
			if alias == config.ActiveAccount {
				status = " (active)"
			}
			// Truncate address for display
			shortAddr := address[:6] + "..." + address[len(address)-4:]
			fmt.Printf("   • %s: %s%s\n", alias, shortAddr, status)
		}
		return nil
	},
}

var authUseCmd = &cobra.Command{
	Use:   "use [alias]",
	Short: "Switch to a different account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		alias := args[0]
		
		config, err := loadConfig()
		if err != nil {
			return fmt.Errorf("no configuration found. Run 'grapevine auth login --alias %s' to add the account", alias)
		}

		// Ensure Accounts map is initialized
		if config.Accounts == nil {
			return fmt.Errorf("no accounts configured. Run 'grapevine auth login --alias %s' to add the account", alias)
		}

		if _, exists := config.Accounts[alias]; !exists {
			return fmt.Errorf("account '%s' not found. Run 'grapevine auth list' to see available accounts", alias)
		}

		// Verify the key exists in keyring
		_, err = getPrivateKey(alias)
		if err != nil {
			return fmt.Errorf("private key for account '%s' not found in keyring. Run 'grapevine auth login --alias %s' to re-add it", alias, alias)
		}

		config.ActiveAccount = alias
		if err := saveConfig(config); err != nil {
			return fmt.Errorf("failed to save config: %v", err)
		}

		address := config.Accounts[alias]
		shortAddr := address[:6] + "..." + address[len(address)-4:]
		fmt.Printf("\n✅ Switched to account: %s (%s)\n", alias, shortAddr)
		return nil
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout [alias]",
	Short: "Remove account (or all if no alias specified)",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := loadConfig()
		if err != nil {
			fmt.Println("\n⚠️  No configuration to remove")
			return nil
		}

		// Ensure Accounts map is initialized
		if config.Accounts == nil {
			fmt.Println("\n⚠️  No configuration to remove")
			return nil
		}

		if len(args) == 0 {
			// Remove all accounts
			for alias := range config.Accounts {
				deletePrivateKey(alias) // Remove from keyring (ignore errors)
			}
			
			// Remove config file
			_, configFile := getConfigPath()
			if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("error removing configuration: %v", err)
			}
			
			fmt.Println("\n✅ All accounts and configuration removed")
		} else {
			// Remove specific account
			alias := args[0]
			if _, exists := config.Accounts[alias]; !exists {
				return fmt.Errorf("account '%s' not found", alias)
			}

			// Remove from keyring
			if err := deletePrivateKey(alias); err != nil {
				fmt.Printf("Warning: failed to remove key from keyring: %v\n", err)
			}

			// Remove from config
			delete(config.Accounts, alias)
			
			// If this was the active account, clear it
			if config.ActiveAccount == alias {
				config.ActiveAccount = ""
			}

			// If no accounts left, remove config file
			if len(config.Accounts) == 0 {
				_, configFile := getConfigPath()
				os.Remove(configFile)
				fmt.Printf("\n✅ Account '%s' removed (last account - configuration cleared)\n", alias)
			} else {
				// Save updated config
				if err := saveConfig(config); err != nil {
					return fmt.Errorf("failed to save config: %v", err)
				}
				fmt.Printf("\n✅ Account '%s' removed\n", alias)
			}
		}
		return nil
	},
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show SDK and network information",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("\n🍇 Grapevine SDK Info")
		fmt.Printf("   Version: %s\n", version)
		fmt.Printf("   Runtime: go %s\n", runtime.Version())
		
		home, _ := os.UserHomeDir()
		configFile := filepath.Join(home, ".grapevine", "config.json")
		
		var config Config
		if data, err := os.ReadFile(configFile); err == nil {
			json.Unmarshal(data, &config)
			fmt.Printf("   Default Network: %s\n", config.Network)
		} else {
			fmt.Println("   Default Network: testnet")
		}

		client, err := getClient(false)
		if err == nil && client.privateKey != nil {
			if client.isTestnet {
				fmt.Println("   Active Network: Testnet")
				fmt.Println("   Chain: base-sepolia")
			} else {
				fmt.Println("   Active Network: Mainnet")
				fmt.Println("   Chain: base")
			}
			fmt.Printf("   Wallet: %s\n", client.address.Hex())
		} else if config.ActiveAccount != "" {
			if address, exists := config.Accounts[config.ActiveAccount]; exists {
				networkStr := "Testnet"
				if config.Network == "mainnet" {
					networkStr = "Mainnet"
				}
				fmt.Printf("   Active Network: %s\n", networkStr)
				fmt.Printf("   Wallet: %s\n", address)
				fmt.Println("   ⚠️  Private key not provided - some operations require --key flag")
			}
		} else {
			fmt.Println("   ⚠️  No authentication configured")
			fmt.Println("   Run 'grapevine auth login' to configure")
		}

		if !config.ConfiguredAt.IsZero() {
			fmt.Printf("\n   Last configured: %s\n", config.ConfiguredAt.Format(time.RFC3339))
		}
		return nil
	},
}

var walletCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Wallet information and utilities",
}

var walletInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show current wallet information",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getClient(true)
		if err != nil {
			return err
		}

		fmt.Println("\n💼 Wallet Information:")
		fmt.Printf("   Address: %s\n", client.address.Hex())
		fmt.Printf("   Network: %s\n", client.network)
		if client.isTestnet {
			fmt.Println("   Environment: Testnet")
			fmt.Printf("   Chain ID: %s\n", client.getChainID())
			fmt.Printf("   USDC Contract: %s\n", client.getUSDCContractAddress())
		} else {
			fmt.Println("   Environment: Mainnet")
			fmt.Printf("   Chain ID: %s\n", client.getChainID())
			fmt.Printf("   USDC Contract: %s\n", client.getUSDCContractAddress())
		}
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("grapevine version %s\n", version)
	},
}

func init() {
	// Feed commands
	feedCreateCmd.Flags().StringP("description", "D", "", "Feed description")
	feedCreateCmd.Flags().StringP("tags", "t", "", "Comma-separated tags")
	feedCmd.AddCommand(feedCreateCmd)

	feedListCmd.Flags().StringP("owner", "o", "", "Filter by owner wallet address")
	feedListCmd.Flags().String("tags", "", "Filter by comma-separated tags")
	feedListCmd.Flags().BoolP("active", "a", false, "Only show active feeds")
	feedListCmd.Flags().IntP("limit", "l", 10, "Limit results")
	feedListCmd.Flags().String("category", "", "Filter by category ID")
	feedListCmd.Flags().Int("min-entries", 0, "Minimum number of entries")
	feedListCmd.Flags().Int("min-age", 0, "Minimum age in days")
	feedListCmd.Flags().Int("max-age", 0, "Maximum age in days")
	feedListCmd.Flags().String("page", "", "Page token for pagination")
	feedCmd.AddCommand(feedListCmd)

	feedCmd.AddCommand(feedGetCmd)

	feedUpdateCmd.Flags().String("name", "", "New feed name")
	feedUpdateCmd.Flags().StringP("description", "D", "", "New feed description")
	feedUpdateCmd.Flags().String("tags", "", "Comma-separated tags")
	feedUpdateCmd.Flags().Bool("active", false, "Set feed as active")
	feedUpdateCmd.Flags().Bool("inactive", false, "Set feed as inactive")
	feedUpdateCmd.Flags().String("category", "", "Category ID")
	feedUpdateCmd.Flags().String("image", "", "Image URL")
	feedCmd.AddCommand(feedUpdateCmd)

	feedDeleteCmd.Flags().BoolP("force", "f", false, "Skip confirmation")
	feedCmd.AddCommand(feedDeleteCmd)

	feedMyFeedsCmd.Flags().IntP("limit", "l", 10, "Limit results")
	feedCmd.AddCommand(feedMyFeedsCmd)

	// Entry commands  
	entryAddCmd.Flags().StringP("title", "T", "", "Entry title")
	entryAddCmd.Flags().StringP("description", "D", "", "Entry description")
	entryAddCmd.Flags().StringP("mime", "m", "", "MIME type")
	entryAddCmd.Flags().BoolP("file", "f", false, "Treat content as file path")
	entryAddCmd.Flags().BoolP("paid", "p", false, "Make this a paid entry")
	entryAddCmd.Flags().String("price", "1000000", "Price in USDC")
	entryAddCmd.Flags().String("tags", "", "Comma-separated tags")
	entryAddCmd.Flags().String("metadata", "", "JSON metadata")
	entryAddCmd.Flags().Int("expires", 0, "Entry expiration in hours from now")
	entryCmd.AddCommand(entryAddCmd)

	entryCmd.AddCommand(entryGetCmd)

	entryDeleteCmd.Flags().BoolP("force", "f", false, "Skip confirmation")
	entryCmd.AddCommand(entryDeleteCmd)

	entryListCmd.Flags().BoolP("free", "f", false, "Only show free entries")
	entryListCmd.Flags().BoolP("paid", "p", false, "Only show paid entries")
	entryListCmd.Flags().IntP("limit", "l", 20, "Limit results")
	entryListCmd.Flags().BoolP("active", "a", false, "Only show active entries")
	entryListCmd.Flags().String("tags", "", "Filter by comma-separated tags")
	entryListCmd.Flags().String("page", "", "Page token for pagination")
	entryCmd.AddCommand(entryListCmd)

	entryBatchCmd.Flags().Int("delay", 1000, "Delay between requests in milliseconds")
	entryBatchCmd.Flags().Bool("stop-on-error", false, "Stop batch processing on first error")
	entryCmd.AddCommand(entryBatchCmd)

	// Auth commands
	authLoginCmd.Flags().StringP("key", "k", "", "Private key")
	authLoginCmd.Flags().StringP("alias", "a", "", "Account alias (default: 'default')")
	authLoginCmd.Flags().StringP("network", "n", "", "Default network (testnet/mainnet)")
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authListCmd)
	authCmd.AddCommand(authUseCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authLogoutCmd)

	// Wallet commands
	walletCmd.AddCommand(walletInfoCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}