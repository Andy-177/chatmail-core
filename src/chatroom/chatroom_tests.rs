//! Tests for the chatroom permission group system.

use anyhow::Result;

use crate::chat::{self, Chat};
use crate::chatroom::{ALL_PERMISSIONS, ChatPermission, create_chatroom};
use crate::contact::ContactId;
use crate::message::Message;
use crate::mimeparser::SystemMessage;
use crate::param::Param;
use crate::test_utils::{TestContext, TestContextManager};

/// Forwards all messages which `from` has sent to `to`.
async fn forward_all(from: &TestContext, to: &TestContext) {
    while let Some(sent) = from.pop_sent_msg_opt().await {
        let _received = to.recv_msg_opt(&sent).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_create_chatroom() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;

    tcm.section("Alice creates a chatroom");
    let chat_id = create_chatroom(&alice, "Chatroom").await?;
    let chat = Chat::load_from_db(&alice, chat_id).await?;
    assert!(chat.is_chatroom());
    assert_eq!(
        chat.get_chatroom_creator(&alice).await?,
        Some(ContactId::SELF)
    );
    assert_eq!(
        chat_id
            .get_contact_permissions(&alice, ContactId::SELF)
            .await?,
        ALL_PERMISSIONS.to_vec()
    );

    tcm.section("The chatroom has the two built-in permission groups");
    let groups = chat_id.get_permission_groups(&alice).await?;
    assert_eq!(groups.len(), 2, "{groups:?}");
    assert_eq!(groups[0].id, 1);
    assert_eq!(groups[0].name, "Owner");
    assert_eq!(groups[0].permissions, ALL_PERMISSIONS.to_vec());
    assert_eq!(groups[1].id, 2);
    assert_eq!(groups[1].name, "Everyone");
    assert!(groups[1].permissions.is_empty());
    assert_eq!(
        chat_id.get_permission_group_members(&alice, 1).await?,
        vec![ContactId::SELF]
    );

    tcm.section("Built-in permission groups cannot be deleted");
    assert!(chat_id.delete_permission_group(&alice, 1).await.is_err());
    assert!(chat_id.delete_permission_group(&alice, 2).await.is_err());

    tcm.section("Normal group chats are no chatrooms");
    let group_id = chat::create_group(&alice, "Group").await?;
    let group = Chat::load_from_db(&alice, group_id).await?;
    assert!(!group.is_chatroom());
    assert_eq!(group.get_chatroom_creator(&alice).await?, None);
    assert!(group_id.get_permission_groups(&alice).await?.is_empty());
    assert!(
        group_id
            .has_permission(&alice, ContactId::SELF, ChatPermission::AddContactToChat)
            .await?
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_chatroom_permissions() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let bob_id = alice.add_or_lookup_contact_id(&bob).await;
    let bob_alice_id = bob.add_or_lookup_contact_id(&alice).await;

    tcm.section("Alice creates a chatroom and adds Bob");
    let chat_id = create_chatroom(&alice, "Chatroom").await?;
    chat::add_contact_to_chat(&alice, chat_id, bob_id).await?;
    // Bob is told about the permissions as soon as he is added.
    forward_all(&alice, &bob).await;
    let sent = alice.send_text(chat_id, "hi").await;
    let bob_chat_id = bob.recv_msg(&sent).await.get_chat_id();
    bob_chat_id.accept(&bob).await?;

    tcm.section("Bob has no permissions and may not change the chatroom");
    assert!(
        chat_id
            .get_contact_permissions(&alice, bob_id)
            .await?
            .is_empty()
    );
    assert!(
        chat::set_chat_name(&bob, bob_chat_id, "Bob was here")
            .await
            .is_err()
    );
    assert!(
        chat::set_chat_description(&bob, bob_chat_id, "Bob was here")
            .await
            .is_err()
    );
    assert!(
        bob_chat_id
            .create_permission_group(&bob, "Bob", &ALL_PERMISSIONS)
            .await
            .is_err()
    );

    tcm.section("Alice makes Bob a moderator");
    let group_id = chat_id
        .create_permission_group(
            &alice,
            "Moderators",
            &[
                ChatPermission::SetChatName,
                ChatPermission::SetChatDescription,
            ],
        )
        .await?;
    assert_eq!(group_id, 3);
    chat_id
        .assign_permission_group(&alice, group_id, bob_id)
        .await?;
    forward_all(&alice, &bob).await;
    assert_eq!(
        chat_id
            .get_permission_group_members(&alice, group_id)
            .await?,
        vec![bob_id]
    );
    assert_eq!(
        chat_id.get_contact_permissions(&alice, bob_id).await?,
        vec![
            ChatPermission::SetChatName,
            ChatPermission::SetChatDescription
        ]
    );

    tcm.section("Bob may now rename and describe the chatroom, but not add members");
    chat::set_chat_name(&bob, bob_chat_id, "Moderated chatroom").await?;
    chat::set_chat_description(&bob, bob_chat_id, "Bob is a moderator").await?;
    assert!(
        chat::add_contact_to_chat(&bob, bob_chat_id, bob_alice_id)
            .await
            .is_err()
    );

    tcm.section("Alice revokes the permissions of Bob");
    chat_id
        .revoke_permission_group(&alice, group_id, bob_id)
        .await?;
    forward_all(&alice, &bob).await;
    assert!(
        chat_id
            .get_contact_permissions(&alice, bob_id)
            .await?
            .is_empty()
    );
    assert!(
        chat::set_chat_name(&bob, bob_chat_id, "Bob was here")
            .await
            .is_err()
    );

    tcm.section("Alice grants permissions to everyone");
    chat_id
        .set_permission_group(&alice, 2, "Everyone", &[ChatPermission::SetChatName])
        .await?;
    assert!(
        chat_id
            .has_permission(&alice, bob_id, ChatPermission::SetChatName)
            .await?
    );
    assert!(
        !chat_id
            .has_permission(&alice, bob_id, ChatPermission::SetChatDescription)
            .await?
    );

    tcm.section("Members of other groups do not get the permissions of 'Everyone'");
    chat_id
        .assign_permission_group(&alice, group_id, bob_id)
        .await?;
    assert!(
        !chat_id
            .has_permission(&alice, bob_id, ChatPermission::SetChatName)
            .await?
    );

    tcm.section("Leaving a chatroom is always possible");
    chat::remove_contact_from_chat(&bob, bob_chat_id, ContactId::SELF).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_chatroom_permissions_are_kept_by_the_creator() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;

    let chat_id = create_chatroom(&alice, "Chatroom").await?;

    tcm.section("Alice removes herself from the 'Owner' group");
    chat_id
        .revoke_permission_group(&alice, 1, ContactId::SELF)
        .await?;
    assert!(
        chat_id
            .get_permission_group_members(&alice, 1)
            .await?
            .is_empty()
    );
    assert!(
        chat_id
            .get_contact_permissions(&alice, ContactId::SELF)
            .await?
            .is_empty()
    );

    tcm.section("Alice may still manage the permission groups");
    assert!(
        chat_id
            .has_permission(
                &alice,
                ContactId::SELF,
                ChatPermission::ManagePermissionGroup
            )
            .await?
    );
    assert!(
        chat_id
            .has_permission(
                &alice,
                ContactId::SELF,
                ChatPermission::AssignPermissionGroup
            )
            .await?
    );
    let group_id = chat_id
        .create_permission_group(&alice, "Admins", &[ChatPermission::AddContactToChat])
        .await?;
    chat_id
        .assign_permission_group(&alice, group_id, ContactId::SELF)
        .await?;

    tcm.section("Alice may not be deprived of the other permissions");
    chat_id
        .set_permission_group(&alice, 1, "Owner", &[])
        .await?;
    assert!(
        !chat_id
            .has_permission(&alice, ContactId::SELF, ChatPermission::SetChatName)
            .await?
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_chatroom_permissions_are_sent_to_members() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let alice_bob_id = alice.add_or_lookup_contact_id(&bob).await;
    let bob_alice_id = bob.add_or_lookup_contact_id(&alice).await;

    tcm.section("Alice creates a chatroom, adds Bob and sends a message");
    let chat_id = create_chatroom(&alice, "Chatroom").await?;
    chat::add_contact_to_chat(&alice, chat_id, alice_bob_id).await?;
    forward_all(&alice, &bob).await;
    let sent = alice.send_text(chat_id, "hi").await;
    let bob_chat_id = bob.recv_msg(&sent).await.get_chat_id();
    bob_chat_id.accept(&bob).await?;

    tcm.section("Bob has received the permissions, but has no permissions himself");
    assert_eq!(bob_chat_id.get_permission_groups(&bob).await?.len(), 2);
    assert!(
        chat::set_chat_name(&bob, bob_chat_id, "Bob was here")
            .await
            .is_err()
    );

    tcm.section("Alice makes Bob a moderator, Bob gets the permission groups");
    let group_id = chat_id
        .create_permission_group(&alice, "Moderators", &[ChatPermission::SetChatName])
        .await?;
    chat_id
        .assign_permission_group(&alice, group_id, alice_bob_id)
        .await?;
    forward_all(&alice, &bob).await;

    let groups = bob_chat_id.get_permission_groups(&bob).await?;
    assert_eq!(groups.len(), 3, "{groups:?}");
    assert_eq!(groups[2].id, group_id);
    assert_eq!(groups[2].name, "Moderators");
    assert_eq!(
        groups[2].permissions,
        vec![ChatPermission::SetChatName],
        "{groups:?}"
    );
    assert_eq!(
        bob_chat_id
            .get_permission_group_members(&bob, group_id)
            .await?,
        vec![ContactId::SELF]
    );
    assert_eq!(
        Chat::load_from_db(&bob, bob_chat_id)
            .await?
            .get_chatroom_creator(&bob)
            .await?,
        Some(bob_alice_id)
    );
    chat::set_chat_name(&bob, bob_chat_id, "Moderated chatroom").await?;

    tcm.section("Bob gets updated permissions");
    chat_id
        .set_permission_group(&alice, group_id, "Moderators", &ALL_PERMISSIONS)
        .await?;
    forward_all(&alice, &bob).await;
    assert_eq!(
        bob_chat_id.get_permission_groups(&bob).await?[2].permissions,
        ALL_PERMISSIONS.to_vec()
    );

    tcm.section("Permission group members are cleaned up when they leave");
    chat::remove_contact_from_chat(&alice, chat_id, alice_bob_id).await?;
    forward_all(&alice, &bob).await;
    assert!(
        bob_chat_id
            .get_permission_group_members(&bob, group_id)
            .await?
            .is_empty()
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_chatroom_permissions_from_members_are_not_applied() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await;
    let alice_bob_id = alice.add_or_lookup_contact_id(&bob).await;
    let alice_charlie_id = alice.add_or_lookup_contact_id(&charlie).await;

    tcm.section("Alice creates a chatroom with Bob and Charlie");
    let chat_id = create_chatroom(&alice, "Chatroom").await?;
    chat::add_contact_to_chat(&alice, chat_id, alice_bob_id).await?;
    chat::add_contact_to_chat(&alice, chat_id, alice_charlie_id).await?;
    let sent = alice.send_text(chat_id, "hi").await;
    let bob_chat_id = bob.recv_msg(&sent).await.get_chat_id();
    let charlie_chat_id = charlie.recv_msg(&sent).await.get_chat_id();
    bob_chat_id.accept(&bob).await?;
    charlie_chat_id.accept(&charlie).await?;
    forward_all(&alice, &bob).await;
    assert_eq!(bob_chat_id.get_permission_groups(&bob).await?.len(), 2);

    tcm.section("Charlie sends permissions which he may not manage");
    let mut msg = Message::new_text("Chatroom permissions updated.".to_string());
    msg.hidden = true;
    msg.param.set_cmd(SystemMessage::ChatroomPermissions);
    msg.param.set(
        Param::Arg,
        r#"{"creator":"","groups":[{"id":1,"name":"Charlie","permissions":"set_chat_name"}],"members":[]}"#,
    );
    let sent = charlie.send_msg(charlie_chat_id, &mut msg).await;
    let _received = bob.recv_msg_opt(&sent).await;

    tcm.section("Bob ignored the permissions of Charlie");
    let groups = bob_chat_id.get_permission_groups(&bob).await?;
    assert_eq!(groups[0].name, "Owner", "{groups:?}");
    assert_eq!(groups[0].permissions, ALL_PERMISSIONS.to_vec());

    Ok(())
}
