package account_abstraction

import (
	"context"
	"crypto/sha256"
	"fmt"

	account_abstractionv1 "cosmossdk.io/api/cosmos/accounts/interfaces/account_abstraction/v1"
	multisigv1 "cosmossdk.io/api/cosmos/accounts/testing/multisig/v1"
	"cosmossdk.io/collections"
	"cosmossdk.io/x/accounts/accountstd"
	"cosmossdk.io/x/accounts/internal/implementation"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var _ accountstd.Interface = (*WeightedMultiSigAccount)(nil)

var (
	MembersPrefix = collections.NewPrefix(0)
)

func NewWeightedMultiSigAccount(d accountstd.Dependencies) (WeightedMultiSigAccount, error) {
	return WeightedMultiSigAccount{
		Members:  collections.NewMap[[]byte, uint64](d.SchemaBuilder, MembersPrefix, "members", collections.BytesKey, collections.Uint64Value),
		Sequence: collections.NewSequence(d.SchemaBuilder, SequencePrefix, "sequence"),
	}, nil
}

type WeightedMultiSigAccount struct {
	// Members is a map of public keys to their weights.
	//*secp256k1.PubKey is the key type.
	Members  collections.Map[[]byte, uint64]
	Sequence collections.Sequence
}

func (a WeightedMultiSigAccount) Init(ctx context.Context, msg *multisigv1.MsgInit) (*multisigv1.MsgInitResponse, error) {
	for _, v := range msg.Members {
		err := a.Members.Set(ctx, v.PubKeyBytes, v.Weight)
		if err != nil {
			return nil, err
		}
	}
	return &multisigv1.MsgInitResponse{}, nil
}

// Authenticate authenticates the account, auth always passess.
func (a WeightedMultiSigAccount) Authenticate(ctx context.Context, msg *account_abstractionv1.MsgAuthenticate) (*account_abstractionv1.MsgAuthenticateResponse, error) {
	if msg.UserOperation.AuthenticationMethod != "secp256k1" {
		return nil, fmt.Errorf("authentication method not supported")
	}

	// naive hash of the messages
	bytesToHash := []byte{}
	for _, v := range msg.UserOperation.ExecutionMessages {
		bytesToHash = append(bytesToHash, []byte(v.TypeUrl)...)
		bytesToHash = append(bytesToHash, v.Value...)
	}
	hash := sha256.Sum256(bytesToHash)

	sigs, err := parseSigs(msg.UserOperation.AuthenticationData)

	if err != nil {
		return nil, err
	}

	totalWeight := uint64(0)
	pass := false

	for _, sig := range sigs {
		pkey, _, err := ecdsa.RecoverCompact(sig, hash[:])
		if err != nil {
			return nil, err
		}

		weight, err := a.Members.Get(ctx, pkey.SerializeCompressed())
		if err != nil {
			return nil, err
		}

		totalWeight += weight
		if totalWeight > 666 { // TODO: make this configurable
			pass = true
			break
		}
	}

	if !pass {
		return nil, fmt.Errorf("not enough weight: %d", totalWeight)
	}

	_, err = a.Sequence.Next(ctx)
	return &account_abstractionv1.MsgAuthenticateResponse{}, err
}

func parseSigs(sigs []byte) ([][]byte, error) { //([]sig, error) {
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no signatures")
	}
	if len(sigs)%65 != 0 {
		return nil, fmt.Errorf("invalid signature length")
	}
	allSigs := make([][]byte, len(sigs)/65)
	// var allSigs []sig
	for i := 0; i < len(sigs); i += 65 {
		allSigs[i/65] = sigs[i : i+65]
	}
	// 	v, r, s, err := parseVRS(sigs[i : i+65])
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	allSigs = append(allSigs, sig{V: v, R: r, S: s})
	// }
	return allSigs, nil
}

func parseVRS(vrs []byte) (uint8, [32]byte, [32]byte, error) {
	if len(vrs) != 65 {
		return 0, [32]byte{}, [32]byte{}, fmt.Errorf("invalid signature length")
	}
	v := vrs[0]
	r := [32]byte{}
	copy(r[:], vrs[1:33])
	s := [32]byte{}
	copy(s[:], vrs[33:65])
	return v, r, s, nil
}

type sig struct {
	V uint8
	R [32]byte
	S [32]byte
}

// RegisterExecuteHandlers implements implementation.Account.
func (a WeightedMultiSigAccount) RegisterExecuteHandlers(builder *implementation.ExecuteBuilder) {
	accountstd.RegisterExecuteHandler(builder, a.Authenticate) // implements account_abstraction
}

// RegisterInitHandler implements implementation.Account.
func (a WeightedMultiSigAccount) RegisterInitHandler(builder *implementation.InitBuilder) {
	accountstd.RegisterInitHandler(builder, a.Init)
}

// QueryAuthenticateMethods queries the authentication methods of the account.
func (a WeightedMultiSigAccount) QueryAuthenticateMethods(ctx context.Context, req *account_abstractionv1.QueryAuthenticationMethods) (*account_abstractionv1.QueryAuthenticationMethodsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

// RegisterQueryHandlers implements implementation.Account.
func (a WeightedMultiSigAccount) RegisterQueryHandlers(builder *implementation.QueryBuilder) {
	accountstd.RegisterQueryHandler(builder, a.QueryAuthenticateMethods) // implements account_abstraction
}
