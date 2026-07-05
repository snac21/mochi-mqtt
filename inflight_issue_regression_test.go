// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt

package mqtt

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/stretchr/testify/require"
)

func TestInflightQuotaUsesSingleLockedState(t *testing.T) {
	inflightType := reflect.TypeOf(Inflight{})

	for _, name := range []string{
		"receiveQuota",
		"sendQuota",
		"maximumReceiveQuota",
		"maximumSendQuota",
	} {
		_, ok := inflightType.FieldByName(name)
		require.False(t, ok, "quota mirror field %s must not be reintroduced", name)
	}
}

func TestInflightCloneCopiesQuotaSnapshot(t *testing.T) {
	i := NewInflights()
	i.ResetReceiveQuota(3)
	i.ResetSendQuota(4)
	i.DecreaseReceiveQuota()
	i.DecreaseSendQuota()
	i.DecreaseSendQuota()
	i.Set(packets.Packet{PacketID: 7})

	clone := i.Clone()

	require.Equal(t, int32(2), clone.ReceiveQuota())
	require.Equal(t, int32(3), clone.MaximumReceiveQuota())
	require.Equal(t, int32(2), clone.SendQuota())
	require.Equal(t, int32(4), clone.MaximumSendQuota())
	require.Equal(t, 1, clone.Len())

	i.DecreaseReceiveQuota()
	i.IncreaseSendQuota()
	i.Set(packets.Packet{PacketID: 8})

	require.Equal(t, int32(2), clone.ReceiveQuota())
	require.Equal(t, int32(2), clone.SendQuota())
	require.Equal(t, 1, clone.Len())
}

func TestInflightNextImmediateDoesNotTakeNestedMapLock(t *testing.T) {
	require.False(t, methodCallsSelector(t, "inflight.go", "NextImmediate", "Lock"))
	require.False(t, methodCallsSelector(t, "inflight.go", "NextImmediate", "RLock"))
}

func methodCallsSelector(t *testing.T, filename, methodName, selector string) bool {
	t.Helper()

	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filename, nil, 0)
	require.NoError(t, err)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != methodName || fn.Body == nil {
			continue
		}

		found := false
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			if sel.Sel.Name == selector {
				found = true
				return false
			}

			return true
		})

		return found
	}

	t.Fatalf("method %s not found in %s", methodName, filename)
	return false
}
