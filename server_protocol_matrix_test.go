// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package mqtt

import (
	"bytes"
	"testing"

	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/stretchr/testify/require"
)

func encodeProtocolPacket(t *testing.T, pk packets.Packet) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	var err error
	switch pk.FixedHeader.Type {
	case packets.Connect:
		err = pk.ConnectEncode(buf)
	case packets.Connack:
		err = pk.ConnackEncode(buf)
	case packets.Publish:
		err = pk.PublishEncode(buf)
	case packets.Puback:
		err = pk.PubackEncode(buf)
	case packets.Pubrec:
		err = pk.PubrecEncode(buf)
	case packets.Pubrel:
		err = pk.PubrelEncode(buf)
	case packets.Pubcomp:
		err = pk.PubcompEncode(buf)
	case packets.Subscribe:
		err = pk.SubscribeEncode(buf)
	case packets.Suback:
		err = pk.SubackEncode(buf)
	case packets.Unsubscribe:
		err = pk.UnsubscribeEncode(buf)
	case packets.Unsuback:
		err = pk.UnsubackEncode(buf)
	case packets.Pingreq:
		err = pk.PingreqEncode(buf)
	case packets.Pingresp:
		err = pk.PingrespEncode(buf)
	case packets.Disconnect:
		err = pk.DisconnectEncode(buf)
	case packets.Auth:
		err = pk.AuthEncode(buf)
	default:
		t.Fatalf("unsupported packet type %d", pk.FixedHeader.Type)
	}
	require.NoError(t, err)
	return buf.Bytes()
}

func decodeProtocolPacket(t *testing.T, raw []byte, protocolVersion byte) packets.Packet {
	t.Helper()
	require.NotEmpty(t, raw)
	fh := packets.FixedHeader{}
	require.NoError(t, fh.Decode(raw[0]))
	remaining, n := decodeTestRemainingLength(t, raw[1:])
	fh.Remaining = remaining
	pk := packets.Packet{FixedHeader: fh, ProtocolVersion: protocolVersion}
	body := raw[1+n:]
	var err error
	switch fh.Type {
	case packets.Connect:
		err = pk.ConnectDecode(body)
	case packets.Connack:
		err = pk.ConnackDecode(body)
	case packets.Publish:
		err = pk.PublishDecode(body)
	case packets.Puback:
		err = pk.PubackDecode(body)
	case packets.Pubrec:
		err = pk.PubrecDecode(body)
	case packets.Pubrel:
		err = pk.PubrelDecode(body)
	case packets.Pubcomp:
		err = pk.PubcompDecode(body)
	case packets.Subscribe:
		err = pk.SubscribeDecode(body)
	case packets.Suback:
		err = pk.SubackDecode(body)
	case packets.Unsubscribe:
		err = pk.UnsubscribeDecode(body)
	case packets.Unsuback:
		err = pk.UnsubackDecode(body)
	case packets.Pingreq:
		err = pk.PingreqDecode(body)
	case packets.Pingresp:
		err = pk.PingrespDecode(body)
	case packets.Disconnect:
		err = pk.DisconnectDecode(body)
	case packets.Auth:
		err = pk.AuthDecode(body)
	default:
		t.Fatalf("unsupported packet type %d", fh.Type)
	}
	require.NoError(t, err)
	return pk
}

func decodeTestRemainingLength(t *testing.T, raw []byte) (int, int) {
	t.Helper()
	multiplier := 1
	value := 0
	for i, b := range raw {
		value += int(b&127) * multiplier
		if b&128 == 0 {
			return value, i + 1
		}
		multiplier *= 128
	}
	t.Fatalf("remaining length did not terminate")
	return 0, 0
}

func requireProtocolRoundTrip(t *testing.T, raw []byte, protocolVersion byte) packets.Packet {
	t.Helper()
	pk := decodeProtocolPacket(t, raw, protocolVersion)
	encoded := encodeProtocolPacket(t, pk)
	decodedAgain := decodeProtocolPacket(t, encoded, protocolVersion)
	require.Equal(t, pk.FixedHeader.Type, decodedAgain.FixedHeader.Type)
	require.Equal(t, pk.FixedHeader.Qos, decodedAgain.FixedHeader.Qos)
	require.Equal(t, pk.FixedHeader.Dup, decodedAgain.FixedHeader.Dup)
	require.Equal(t, pk.FixedHeader.Retain, decodedAgain.FixedHeader.Retain)
	require.Equal(t, pk.PacketID, decodedAgain.PacketID)
	require.Equal(t, pk.TopicName, decodedAgain.TopicName)
	require.Equal(t, pk.Payload, decodedAgain.Payload)
	require.Equal(t, pk.ReasonCode, decodedAgain.ReasonCode)
	return pk
}

func TestProtocolUpstreamPacketFormatMatrix(t *testing.T) {
	tests := []struct {
		name            string
		protocolVersion byte
		packetType      byte
		fixture         byte
	}{
		{"mqtt31_connect", 3, packets.Connect, packets.TConnectMqtt31},
		{"mqtt311_connect", 4, packets.Connect, packets.TConnectMqtt311},
		{"mqtt5_connect", 5, packets.Connect, packets.TConnectMqtt5},
		{"mqtt311_publish_qos0", 4, packets.Publish, packets.TPublishBasic},
		{"mqtt5_publish_qos0", 5, packets.Publish, packets.TPublishMqtt5},
		{"mqtt311_publish_qos1", 4, packets.Publish, packets.TPublishQos1},
		{"mqtt5_publish_qos1", 5, packets.Publish, packets.TPublishQos1Mqtt5},
		{"mqtt311_publish_qos2", 4, packets.Publish, packets.TPublishQos2},
		{"mqtt5_publish_qos2", 5, packets.Publish, packets.TPublishQos2Mqtt5},
		{"mqtt311_puback", 4, packets.Puback, packets.TPuback},
		{"mqtt5_puback", 5, packets.Puback, packets.TPubackMqtt5},
		{"mqtt311_subscribe", 4, packets.Subscribe, packets.TSubscribe},
		{"mqtt5_subscribe", 5, packets.Subscribe, packets.TSubscribeMqtt5},
		{"mqtt311_unsubscribe", 4, packets.Unsubscribe, packets.TUnsubscribe},
		{"mqtt5_unsubscribe", 5, packets.Unsubscribe, packets.TUnsubscribeMqtt5},
		{"mqtt311_pingreq", 4, packets.Pingreq, packets.TPingreq},
		{"mqtt311_disconnect", 4, packets.Disconnect, packets.TDisconnect},
		{"mqtt5_disconnect", 5, packets.Disconnect, packets.TDisconnectMqtt5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := packets.TPacketData[tt.packetType].Get(tt.fixture)
			pk := requireProtocolRoundTrip(t, fixture.RawBytes, tt.protocolVersion)
			require.Equal(t, tt.packetType, pk.FixedHeader.Type)
			require.Equal(t, tt.protocolVersion, pk.ProtocolVersion)
		})
	}
}

func TestProtocolDownstreamPacketFormatMatrix(t *testing.T) {
	tests := []struct {
		name            string
		protocolVersion byte
		packetType      byte
		fixture         byte
	}{
		{"mqtt311_connack", 4, packets.Connack, packets.TConnackAcceptedNoSession},
		{"mqtt5_connack", 5, packets.Connack, packets.TConnackAcceptedMqtt5},
		{"mqtt311_publish_qos0", 4, packets.Publish, packets.TPublishBasic},
		{"mqtt5_publish_qos0", 5, packets.Publish, packets.TPublishMqtt5},
		{"mqtt311_puback", 4, packets.Puback, packets.TPuback},
		{"mqtt5_puback", 5, packets.Puback, packets.TPubackMqtt5},
		{"mqtt311_suback", 4, packets.Suback, packets.TSuback},
		{"mqtt5_suback", 5, packets.Suback, packets.TSubackMqtt5},
		{"mqtt311_unsuback", 4, packets.Unsuback, packets.TUnsuback},
		{"mqtt5_unsuback", 5, packets.Unsuback, packets.TUnsubackMqtt5},
		{"mqtt311_pingresp", 4, packets.Pingresp, packets.TPingresp},
		{"mqtt311_disconnect", 4, packets.Disconnect, packets.TDisconnect},
		{"mqtt5_disconnect", 5, packets.Disconnect, packets.TDisconnectMqtt5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := packets.TPacketData[tt.packetType].Get(tt.fixture)
			pk := requireProtocolRoundTrip(t, fixture.RawBytes, tt.protocolVersion)
			require.Equal(t, tt.packetType, pk.FixedHeader.Type)
			require.Equal(t, tt.protocolVersion, pk.ProtocolVersion)
		})
	}
}
