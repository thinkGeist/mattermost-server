// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package slashcommands

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mattermost/mattermost/server/v8/channels/testlib"

	"github.com/mattermost/mattermost/server/v8/channels/app"
	"github.com/mattermost/mattermost/server/v8/platform/services/remotecluster"

	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/public/model"
)

func TestShareProviderDoCommand(t *testing.T) {
	t.Run("share command sends a websocket channel converted event", func(t *testing.T) {
		th := setup(t).initBasic()
		defer th.tearDown()

		th.addPermissionToRole(model.PermissionManageSharedChannels.Id, th.BasicUser.Roles)

		mockSyncService := app.NewMockSharedChannelService(nil, app.MockOptionSharedChannelServiceWithActive(true))
		th.Server.SetSharedChannelSyncService(mockSyncService)
		remoteClusterService, err := remotecluster.NewRemoteClusterService(th.Server, th.App)
		require.NoError(t, err)

		th.Server.SetRemoteClusterService(remoteClusterService)
		testCluster := &testlib.FakeClusterInterface{}
		th.Server.Platform().SetCluster(testCluster)

		err = remoteClusterService.Start()
		require.NoError(t, err)
		defer remoteClusterService.Shutdown()

		commandProvider := ShareProvider{}
		channel := th.CreateChannel(th.BasicTeam, WithShared(false))

		args := &model.CommandArgs{
			T:         func(s string, args ...any) string { return s },
			ChannelId: channel.Id,
			UserId:    th.BasicUser.Id,
			TeamId:    th.BasicTeam.Id,
			Command:   "/share-channel share",
		}

		response := commandProvider.DoCommand(th.App, th.Context, args, "")
		require.Equal(t, "##### "+args.T("api.command_share.channel_shared"), response.Text)

		channelConvertedMessages := testCluster.SelectMessages(func(msg *model.ClusterMessage) bool {
			event, err := model.WebSocketEventFromJSON(bytes.NewReader(msg.Data))
			return err == nil && event.EventType() == model.WebsocketEventChannelConverted
		})
		assert.Len(t, channelConvertedMessages, 1) // one msg for share creation
	})

	t.Run("unshare command sends a websocket channel converted event", func(t *testing.T) {
		th := setup(t).initBasic()
		defer th.tearDown()

		th.addPermissionToRole(model.PermissionManageSharedChannels.Id, th.BasicUser.Roles)

		mockSyncService := app.NewMockSharedChannelService(nil)
		th.Server.SetSharedChannelSyncService(mockSyncService)
		remoteClusterService, err := remotecluster.NewRemoteClusterService(th.Server, th.App)
		require.NoError(t, err)

		th.Server.SetRemoteClusterService(remoteClusterService)
		testCluster := &testlib.FakeClusterInterface{}
		th.Server.Platform().SetCluster(testCluster)

		err = remoteClusterService.Start()
		require.NoError(t, err)
		defer remoteClusterService.Shutdown()

		commandProvider := ShareProvider{}
		channel := th.CreateChannel(th.BasicTeam, WithShared(true))
		args := &model.CommandArgs{
			T:         func(s string, args ...any) string { return s },
			ChannelId: channel.Id,
			UserId:    th.BasicUser.Id,
			TeamId:    th.BasicTeam.Id,
			Command:   "/share-channel unshare",
		}

		response := commandProvider.DoCommand(th.App, th.Context, args, "")
		require.Equal(t, "##### "+args.T("api.command_share.shared_channel_unavailable"), response.Text)

		channelConvertedMessages := testCluster.SelectMessages(func(msg *model.ClusterMessage) bool {
			event, err := model.WebSocketEventFromJSON(bytes.NewReader(msg.Data))
			return err == nil && event.EventType() == model.WebsocketEventChannelConverted
		})
		require.Len(t, channelConvertedMessages, 2) // one msg for share creation, one for unshare.
	})
}
