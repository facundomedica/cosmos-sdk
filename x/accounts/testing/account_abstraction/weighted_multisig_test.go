package account_abstraction

import (
	"crypto/sha256"
	"testing"

	account_abstractionv1 "cosmossdk.io/api/cosmos/accounts/interfaces/account_abstraction/v1"
	multisigv1 "cosmossdk.io/api/cosmos/accounts/testing/multisig/v1"
	accountsv1 "cosmossdk.io/api/cosmos/accounts/v1"
	bankv1beta1 "cosmossdk.io/api/cosmos/bank/v1beta1"
	v1beta1 "cosmossdk.io/api/cosmos/base/v1beta1"
	"cosmossdk.io/collections"
	"cosmossdk.io/collections/colltest"
	"cosmossdk.io/x/accounts/accountstd"
	"github.com/cosmos/cosmos-proto/anyutil"
	"github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	dcredsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestAuthenticate(t *testing.T) {
	sk, ctx := colltest.MockStore()
	sb := collections.NewSchemaBuilder(sk)
	deps := accountstd.Dependencies{
		SchemaBuilder: sb,
		AddressCodec:  address.NewBech32Codec("cosmos"),
	}
	ms, err := NewWeightedMultiSigAccount(deps)
	require.NoError(t, err)

	keys := []*secp256k1.PrivKey{}

	for i := 0; i < 10; i++ {
		k := secp256k1.GenPrivKey()
		require.NoError(t, err)
		keys = append(keys, k)
	}

	members := []*multisigv1.Member{}
	for _, k := range keys {
		members = append(members, &multisigv1.Member{
			PubKeyBytes: k.PubKey().Bytes(),
			Weight:      100, // * 10 = 1000
		})
	}
	_, err = ms.Init(ctx, &multisigv1.MsgInit{
		Members: members,
	})
	require.NoError(t, err)

	msgs := intoAny(t, &bankv1beta1.MsgSend{
		FromAddress: "blabla",
		ToAddress:   "bleble",
		Amount:      coins(t, "2000stake"),
	})

	bytesToHash := []byte{}
	for _, v := range msgs {
		bytesToHash = append(bytesToHash, []byte(v.TypeUrl)...)
		bytesToHash = append(bytesToHash, v.Value...)
	}

	hash := sha256.Sum256(bytesToHash)

	sigs := []byte{}
	for _, k := range keys {
		// this is what the sdk does but we remove the recovery id, which I need here
		priv := dcredsecp256k1.PrivKeyFromBytes(k.Key)
		sig := ecdsa.SignCompact(priv, hash[:], false)

		require.NoError(t, err)
		sigs = append(sigs, sig...)
		break
	}

	// test authentication
	_, err = ms.Authenticate(ctx, &account_abstractionv1.MsgAuthenticate{
		UserOperation: &accountsv1.UserOperation{
			AuthenticationMethod: "secp256k1",
			AuthenticationData:   sigs,
			ExecutionMessages:    msgs,
		},
	})
	require.NoError(t, err)

}

func intoAny(t *testing.T, msgs ...proto.Message) (anys []*anypb.Any) {
	t.Helper()
	for _, msg := range msgs {
		any, err := anyutil.New(msg)
		require.NoError(t, err)
		anys = append(anys, any)
	}
	return
}

func coins(t *testing.T, s string) []*v1beta1.Coin {
	t.Helper()
	coins, err := sdk.ParseCoinsNormalized(s)
	require.NoError(t, err)
	coinsv2 := make([]*v1beta1.Coin, len(coins))
	for i, coin := range coins {
		coinsv2[i] = &v1beta1.Coin{
			Denom:  coin.Denom,
			Amount: coin.Amount.String(),
		}
	}
	return coinsv2
}
