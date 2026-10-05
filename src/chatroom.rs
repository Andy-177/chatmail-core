//! # Chatrooms
//!
//! A chatroom is a group chat with a permission group system.
//! Chatrooms are a superset of group chats:
//! Everything that can be done with group chats
//! can be done with chatrooms as well.
//!
//! Permissions are granted by [permission groups](PermissionGroup):
//! All members of a permission group get the permissions of that group.
//! Contacts which are not a member of any permission group
//! get the permissions of the built-in "Everyone" group.
//! If a contact is a member of at least one permission group,
//! the permissions of the "Everyone" group are not granted to them at all,
//! i.e. the other permission groups fully replace the "Everyone" group.
//!
//! Every chatroom has the following two built-in permission groups
//! which cannot be deleted,
//! but their names and permissions can be changed:
//!
//! - "Owner" has all permissions by default.
//!   The creator of the chatroom is a member of this group,
//!   although the creator may remove themselves from it.
//! - "Everyone" has no permissions by default.
//!
//! The creator of the chatroom, see [`Chat::get_chatroom_creator`],
//! can never be deprived of [`ChatPermission::ManagePermissionGroup`]
//! and [`ChatPermission::AssignPermissionGroup`].
//!
//! Leaving a chatroom is always possible for all members.
//! This is a hidden permission which cannot be disabled,
//! therefore nobody can be locked into a chatroom.
//!
//! Chatrooms are created using [`create_chatroom`].
//! The permission groups are stored in the database
//! and are sent to other members and to our own devices
//! as a hidden system message,
//! see [`SystemMessage::ChatroomPermissions`].
//!
//! New members are told about the permissions as soon as they are added:
//! Adding a member to a chatroom sends the permissions to the members
//! and therefore promotes the chat,
//! even if no other message has been sent to the chat yet.
//!
//! # Limitations
//!
//! Permissions are checked on the device which performs an action,
//! they are not enforced against messages received from other members:
//! A member can still send a message
//! which would not pass the permission check of the receiving device.

use anyhow::{Result, bail, ensure};
use deltachat_contact_tools::sanitize_single_line;
use serde::{Deserialize, Serialize};

use crate::chat::{Chat, ChatId, SyncAction, create_group, send_msg};
use crate::chatlist_events;
use crate::contact::{Contact, ContactId, Origin};
use crate::context::Context;
use crate::events::EventType;
use crate::log::{LogExt as _, warn};
use crate::message::Message;
use crate::mimeparser::SystemMessage;
use crate::param::Param;
use crate::sync;

/// ID of the built-in "Owner" permission group.
const OWNER_GROUP: u32 = 1;

/// ID of the built-in "Everyone" permission group.
const EVERYONE_GROUP: u32 = 2;

/// All chatroom permissions.
pub const ALL_PERMISSIONS: [ChatPermission; 9] = [
    ChatPermission::AddContactToChat,
    ChatPermission::RemoveContactFromChat,
    ChatPermission::SetChatName,
    ChatPermission::SetChatProfileImage,
    ChatPermission::SetChatDescription,
    ChatPermission::SetPinnedMessageState,
    ChatPermission::SetChatEphemeralTimer,
    ChatPermission::ManagePermissionGroup,
    ChatPermission::AssignPermissionGroup,
];

/// A permission of a chatroom.
///
/// Permissions are granted by [permission groups](PermissionGroup),
/// see the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChatPermission {
    /// Adding members using [`crate::chat::add_contact_to_chat`].
    AddContactToChat,

    /// Removing members using [`crate::chat::remove_contact_from_chat`],
    /// this does not include leaving the chatroom.
    RemoveContactFromChat,

    /// Renaming the chatroom using [`crate::chat::set_chat_name`].
    SetChatName,

    /// Changing the avatar of the chatroom using [`crate::chat::set_chat_profile_image`].
    SetChatProfileImage,

    /// Changing the description of the chatroom using [`crate::chat::set_chat_description`].
    SetChatDescription,

    /// Pinning and unpinning messages using [`crate::pinned_messages::set_pinned_state`].
    SetPinnedMessageState,

    /// Setting the ephemeral timer of the chatroom using
    /// [`ChatId::set_ephemeral_timer`].
    SetChatEphemeralTimer,

    /// Creating, changing and deleting permission groups
    /// and granting permissions to permission groups.
    ManagePermissionGroup,

    /// Granting and revoking permission groups of members.
    AssignPermissionGroup,
}

impl ChatPermission {
    /// Returns a short name which is used to store the permission
    /// in the database and to pass it on the wire.
    pub fn key(&self) -> &'static str {
        match self {
            Self::AddContactToChat => "add_contact_to_chat",
            Self::RemoveContactFromChat => "remove_contact_from_chat",
            Self::SetChatName => "set_chat_name",
            Self::SetChatProfileImage => "set_chat_profile_image",
            Self::SetChatDescription => "set_chat_description",
            Self::SetPinnedMessageState => "set_pinned_message_state",
            Self::SetChatEphemeralTimer => "set_chat_ephemeral_timer",
            Self::ManagePermissionGroup => "manage_permission_group",
            Self::AssignPermissionGroup => "assign_permission_group",
        }
    }

    /// Returns the permission with the given [`ChatPermission::key`].
    ///
    /// Returns `None` if the key is unknown,
    /// e.g. because it comes from a newer version.
    pub fn new(key: &str) -> Option<Self> {
        ALL_PERMISSIONS
            .iter()
            .find(|permission| permission.key() == key)
            .copied()
    }
}

/// Serializes permissions to a comma-separated string.
fn permissions_to_string(permissions: &[ChatPermission]) -> String {
    permissions
        .iter()
        .map(|permission| permission.key())
        .collect::<Vec<&str>>()
        .join(",")
}

/// Parses a comma-separated string of [`ChatPermission::key`]s,
/// silently ignoring unknown keys as they may come from a newer version.
fn permissions_from_string(permissions: &str) -> Vec<ChatPermission> {
    permissions
        .split(',')
        .filter_map(ChatPermission::new)
        .collect()
}

/// A group of contacts which share the same chatroom permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGroup {
    /// ID of the group, unique within the chatroom.
    pub id: u32,

    /// Name of the group, e.g. to be displayed to users.
    pub name: String,

    /// Permissions which all members of this group have.
    pub permissions: Vec<ChatPermission>,
}

/// Permission groups of a chatroom as they are passed
/// to other members and to our own devices.
#[derive(Debug, Serialize, Deserialize)]
struct PermissionsJson {
    /// Address of the contact which created the chatroom.
    creator: String,

    /// Permission groups, including the two built-in ones.
    groups: Vec<GroupJson>,

    /// Contacts assigned to permission groups.
    members: Vec<MemberJson>,
}

/// A permission group as it is passed to other members and devices.
#[derive(Debug, Serialize, Deserialize)]
struct GroupJson {
    id: u32,
    name: String,

    /// Comma-separated list of [`ChatPermission::key`]s.
    permissions: String,
}

/// A contact assigned to a permission group
/// as it is passed to other members and devices.
#[derive(Debug, Serialize, Deserialize)]
struct MemberJson {
    group_id: u32,

    /// Address of the contact, which is the fingerprint for key contacts.
    addr: String,
}

/// Creates a new chatroom, see the [module documentation](self).
///
/// The creator of the chatroom is a member of the "Owner" permission group.
pub async fn create_chatroom(context: &Context, name: &str) -> Result<ChatId> {
    let chat_id = create_group(context, name).await?;

    let mut chat = Chat::load_from_db(context, chat_id).await?;
    chat.param
        .set_int(Param::Chatroom, 1)
        .set_int(Param::ChatroomCreator, ContactId::SELF.to_u32() as i32);
    chat.update_param(context).await?;

    insert_group(context, chat_id, OWNER_GROUP, "Owner", &ALL_PERMISSIONS).await?;
    insert_group(context, chat_id, EVERYONE_GROUP, "Everyone", &[]).await?;
    insert_group_member(context, chat_id, OWNER_GROUP, ContactId::SELF).await?;

    broadcast_permissions(context, chat_id, crate::sync::Sync::Sync).await?;
    Ok(chat_id)
}

impl Chat {
    /// Returns `true` if the chat is a chatroom,
    /// i.e. a group chat with a permission group system.
    pub fn is_chatroom(&self) -> bool {
        self.param.get_bool(Param::Chatroom).unwrap_or_default()
    }

    /// Returns the contact which created the chatroom.
    ///
    /// The creator can never be deprived of
    /// [`ChatPermission::ManagePermissionGroup`]
    /// and [`ChatPermission::AssignPermissionGroup`].
    /// Returns `None` if the chat is not a chatroom
    /// or if there is no contact which created it.
    pub async fn get_chatroom_creator(&self, context: &Context) -> Result<Option<ContactId>> {
        if !self.is_chatroom() {
            return Ok(None);
        }
        let Some(id) = self.param.get_int(Param::ChatroomCreator) else {
            return Ok(None);
        };
        let contact_id = ContactId::new(u32::try_from(id)?);
        if contact_id == ContactId::SELF {
            return Ok(Some(contact_id));
        }
        Ok(Contact::real_exists_by_id(context, contact_id)
            .await?
            .then_some(contact_id))
    }
}

impl ChatId {
    /// Returns the permission groups of a chatroom,
    /// ordered by ID.
    ///
    /// The built-in groups "Owner" and "Everyone" are contained
    /// in the result of a chatroom and cannot be deleted.
    /// Groups that are not chatrooms have no permission groups.
    pub async fn get_permission_groups(&self, context: &Context) -> Result<Vec<PermissionGroup>> {
        context
            .sql
            .query_map_vec(
                "SELECT id, name, permissions FROM chatroom_permission_groups
                 WHERE chat_id=?
                 ORDER BY id",
                (*self,),
                |row| {
                    let permissions: String = row.get(2)?;
                    Ok(PermissionGroup {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        permissions: permissions_from_string(&permissions),
                    })
                },
            )
            .await
    }

    /// Creates a new permission group with the given name and permissions
    /// in the chatroom and returns its ID.
    ///
    /// Requires the [`ChatPermission::ManagePermissionGroup`] permission.
    pub async fn create_permission_group(
        &self,
        context: &Context,
        name: &str,
        permissions: &[ChatPermission],
    ) -> Result<u32> {
        let name = sanitize_single_line(name);
        ensure!(!name.is_empty(), "Invalid permission group name");
        ensure_chatroom(context, *self).await?;
        self.check_permission(
            context,
            ContactId::SELF,
            ChatPermission::ManagePermissionGroup,
        )
        .await?;

        let id: u32 = context
            .sql
            .query_row(
                "SELECT IFNULL(MAX(id), 0)+1 FROM chatroom_permission_groups WHERE chat_id=?",
                (*self,),
                |row| Ok(row.get(0)?),
            )
            .await?;
        insert_group(context, *self, id, &name, permissions).await?;

        broadcast_permissions(context, *self, crate::sync::Sync::Sync).await?;
        Ok(id)
    }

    /// Changes the name and the permissions
    /// of a permission group of the chatroom.
    ///
    /// Requires the [`ChatPermission::ManagePermissionGroup`] permission.
    pub async fn set_permission_group(
        &self,
        context: &Context,
        group_id: u32,
        name: &str,
        permissions: &[ChatPermission],
    ) -> Result<()> {
        let name = sanitize_single_line(name);
        ensure!(!name.is_empty(), "Invalid permission group name");
        ensure_chatroom(context, *self).await?;
        self.check_permission(
            context,
            ContactId::SELF,
            ChatPermission::ManagePermissionGroup,
        )
        .await?;

        let changed = context
            .sql
            .execute(
                "UPDATE chatroom_permission_groups SET name=?, permissions=?
                 WHERE chat_id=? AND id=?",
                (&name, permissions_to_string(permissions), *self, group_id),
            )
            .await?;
        ensure!(changed > 0, "Unknown permission group {group_id}");

        broadcast_permissions(context, *self, crate::sync::Sync::Sync).await?;
        Ok(())
    }

    /// Deletes a permission group of the chatroom.
    ///
    /// The built-in groups "Owner" and "Everyone" cannot be deleted.
    ///
    /// Requires the [`ChatPermission::ManagePermissionGroup`] permission.
    pub async fn delete_permission_group(&self, context: &Context, group_id: u32) -> Result<()> {
        ensure_chatroom(context, *self).await?;
        ensure!(
            !matches!(group_id, OWNER_GROUP | EVERYONE_GROUP),
            "Built-in permission groups cannot be deleted"
        );
        self.check_permission(
            context,
            ContactId::SELF,
            ChatPermission::ManagePermissionGroup,
        )
        .await?;

        context
            .sql
            .execute(
                "DELETE FROM chatroom_permission_groups WHERE chat_id=? AND id=?",
                (*self, group_id),
            )
            .await?;
        context
            .sql
            .execute(
                "DELETE FROM chatroom_permission_group_members WHERE chat_id=? AND group_id=?",
                (*self, group_id),
            )
            .await?;

        broadcast_permissions(context, *self, crate::sync::Sync::Sync).await?;
        Ok(())
    }

    /// Returns the contacts which are members
    /// of a permission group of the chatroom, ordered by contact ID.
    pub async fn get_permission_group_members(
        &self,
        context: &Context,
        group_id: u32,
    ) -> Result<Vec<ContactId>> {
        context
            .sql
            .query_map_vec(
                "SELECT contact_id FROM chatroom_permission_group_members
                 WHERE chat_id=? AND group_id=?
                 ORDER BY contact_id",
                (*self, group_id),
                |row| {
                    let id: u32 = row.get(0)?;
                    Ok(ContactId::new(id))
                },
            )
            .await
    }

    /// Assigns a permission group of the chatroom to a contact.
    ///
    /// A contact may be a member of multiple permission groups
    /// and then has the permissions of all of them.
    /// Being a member of the built-in group "Everyone" has no effect:
    /// Its permissions are granted to all contacts
    /// which are not a member of any other permission group.
    ///
    /// Requires the [`ChatPermission::AssignPermissionGroup`] permission.
    pub async fn assign_permission_group(
        &self,
        context: &Context,
        group_id: u32,
        contact_id: ContactId,
    ) -> Result<()> {
        ensure_chatroom(context, *self).await?;
        self.check_permission(
            context,
            ContactId::SELF,
            ChatPermission::AssignPermissionGroup,
        )
        .await?;
        ensure!(
            self.group_exists(context, group_id).await?,
            "Unknown permission group {group_id}"
        );

        insert_group_member(context, *self, group_id, contact_id).await?;
        broadcast_permissions(context, *self, crate::sync::Sync::Sync).await?;
        Ok(())
    }

    /// Removes a contact from a permission group of the chatroom.
    ///
    /// Requires the [`ChatPermission::AssignPermissionGroup`] permission.
    pub async fn revoke_permission_group(
        &self,
        context: &Context,
        group_id: u32,
        contact_id: ContactId,
    ) -> Result<()> {
        ensure_chatroom(context, *self).await?;
        self.check_permission(
            context,
            ContactId::SELF,
            ChatPermission::AssignPermissionGroup,
        )
        .await?;

        context
            .sql
            .execute(
                "DELETE FROM chatroom_permission_group_members
                 WHERE chat_id=? AND group_id=? AND contact_id=?",
                (*self, group_id, contact_id),
            )
            .await?;

        broadcast_permissions(context, *self, crate::sync::Sync::Sync).await?;
        Ok(())
    }

    /// Returns all permissions the contact has in the chatroom,
    /// ordered like [`ALL_PERMISSIONS`].
    pub async fn get_contact_permissions(
        &self,
        context: &Context,
        contact_id: ContactId,
    ) -> Result<Vec<ChatPermission>> {
        let group_ids = self.get_permission_group_ids(context, contact_id).await?;
        let groups = self.get_permission_groups(context).await?;

        let mut permissions = Vec::new();
        for group in groups.iter().filter(|group| group_ids.contains(&group.id)) {
            for permission in &group.permissions {
                if !permissions.contains(permission) {
                    permissions.push(*permission);
                }
            }
        }
        permissions.sort();
        Ok(permissions)
    }

    /// Returns `true` if the contact has the given permission in the chatroom.
    ///
    /// All permissions are granted in chats which are not chatrooms,
    /// so that group chats are not restricted.
    pub async fn has_permission(
        &self,
        context: &Context,
        contact_id: ContactId,
        permission: ChatPermission,
    ) -> Result<bool> {
        let chat = Chat::load_from_db(context, *self).await?;
        if !chat.is_chatroom() {
            return Ok(true);
        }
        if self
            .get_contact_permissions(context, contact_id)
            .await?
            .contains(&permission)
        {
            return Ok(true);
        }

        // The creator of the chatroom can never be deprived of these permissions.
        Ok(matches!(
            permission,
            ChatPermission::ManagePermissionGroup | ChatPermission::AssignPermissionGroup
        ) && chat.get_chatroom_creator(context).await? == Some(contact_id))
    }

    /// Returns an error if the contact misses the given chatroom permission.
    ///
    /// The [`EventType::Error`] event is emitted in this case
    /// so that the user interface can tell the user about the missing permission.
    pub(crate) async fn check_permission(
        &self,
        context: &Context,
        contact_id: ContactId,
        permission: ChatPermission,
    ) -> Result<()> {
        let chat = Chat::load_from_db(context, *self).await?;
        if !chat.is_chatroom() || self.has_permission(context, contact_id, permission).await? {
            return Ok(());
        }
        let error =
            format!("Missing chatroom permission {permission:?} for {contact_id} in {self}.");
        context.emit_event(EventType::Error(error.clone()));
        bail!(error)
    }

    /// Returns the IDs of the permission groups the contact is a member of.
    ///
    /// Contacts which are not a member of any other permission group
    /// are members of the built-in group "Everyone".
    async fn get_permission_group_ids(
        &self,
        context: &Context,
        contact_id: ContactId,
    ) -> Result<Vec<u32>> {
        let ids: Vec<u32> = context
            .sql
            .query_map_vec(
                "SELECT group_id FROM chatroom_permission_group_members
                 WHERE chat_id=? AND contact_id=? AND group_id<>?
                 ORDER BY group_id",
                (*self, contact_id, EVERYONE_GROUP),
                |row| Ok(row.get(0)?),
            )
            .await?;
        Ok(if ids.is_empty() {
            vec![EVERYONE_GROUP]
        } else {
            ids
        })
    }

    /// Returns `true` if the permission group exists in the chatroom.
    async fn group_exists(&self, context: &Context, group_id: u32) -> Result<bool> {
        context
            .sql
            .exists(
                "SELECT 1 FROM chatroom_permission_groups WHERE chat_id=? AND id=?",
                (*self, group_id),
            )
            .await
    }
}

/// Returns an error if the chat is not a chatroom,
/// i.e. permission groups are only available in chatrooms.
async fn ensure_chatroom(context: &Context, chat_id: ChatId) -> Result<()> {
    ensure!(
        Chat::load_from_db(context, chat_id).await?.is_chatroom(),
        "Permission groups are only available in chatrooms"
    );
    Ok(())
}

/// Sends the permission groups of the chatroom
/// to the other members and to our own devices.
///
/// `sync` should be `Nosync`
/// if the permissions are received from another device.
pub(crate) async fn broadcast_permissions(
    context: &Context,
    chat_id: ChatId,
    sync: crate::sync::Sync::Sync,
) -> Result<()> {
    let chat = Chat::load_from_db(context, chat_id).await?;
    if !chat.is_chatroom() {
        return Ok(());
    }
    let json = serialize(context, chat_id).await?;

    if sync.into()
        && let Some(_sync_id) = chat.get_sync_id(context).await?
    {
        chat.sync(context, SyncAction::SetChatroomPermissions(json.clone()))
            .await
            .log_err(context)
            .ok();
    }

    if has_other_members(context, chat_id).await? {
        let mut msg = Message::new_text("Chatroom permissions updated.".to_string());
        msg.hidden = true;
        msg.param.set_cmd(SystemMessage::ChatroomPermissions);
        msg.param.set(Param::Arg, json);
        send_msg(context, chat_id, &mut msg).await?;
    }
    Ok(())
}

/// Returns `true` if the chat has members besides us.
async fn has_other_members(context: &Context, chat_id: ChatId) -> Result<bool> {
    context
        .sql
        .exists(
            "SELECT 1 FROM chats_contacts WHERE chat_id=? AND contact_id<>?",
            (chat_id, ContactId::SELF),
        )
        .await
}

/// Replaces the permission groups of the chatroom with the given JSON.
///
/// This is used for permission groups
/// which are received from other members and devices.
pub(crate) async fn apply_permissions(
    context: &Context,
    chat_id: ChatId,
    json: &str,
) -> Result<()> {
    let data: PermissionsJson = serde_json::from_str(json)?;
    ensure!(
        data.groups.iter().any(|group| group.id == OWNER_GROUP)
            && data.groups.iter().any(|group| group.id == EVERYONE_GROUP),
        "Chatroom permissions without the built-in permission groups"
    );

    let mut members = Vec::new();
    for member in &data.members {
        match Contact::lookup_id_by_addr(context, &member.addr, Origin::Unknown).await? {
            Some(contact_id) => members.push((member.group_id, contact_id)),
            None => warn!(
                context,
                "Chatroom permissions: Unknown contact {:?}.", member.addr
            ),
        }
    }

    // The creator of the chatroom cannot be changed by a permissions message,
    // otherwise a member which may manage the permission groups
    // could take over the chatroom.
    let mut chat = Chat::load_from_db(context, chat_id).await?;
    let creator = match chat.get_chatroom_creator(context).await? {
        Some(creator) => Some(creator),
        None if data.creator.is_empty() => None,
        None => Contact::lookup_id_by_addr(context, &data.creator, Origin::Unknown).await?,
    };
    chat.param.set_int(Param::Chatroom, 1);
    chat.param.set_optional(
        Param::ChatroomCreator,
        creator.map(|contact_id| contact_id.to_u32()),
    );
    chat.update_param(context).await?;

    context
        .sql
        .transaction(|transaction| {
            transaction.execute(
                "DELETE FROM chatroom_permission_groups WHERE chat_id=?",
                (chat_id,),
            )?;
            transaction.execute(
                "DELETE FROM chatroom_permission_group_members WHERE chat_id=?",
                (chat_id,),
            )?;
            for group in &data.groups {
                transaction.execute(
                    "INSERT INTO chatroom_permission_groups (chat_id, id, name, permissions)
                     VALUES (?, ?, ?, ?)",
                    (chat_id, group.id, &group.name, &group.permissions),
                )?;
            }
            for (group_id, contact_id) in &members {
                transaction.execute(
                    "INSERT OR IGNORE INTO chatroom_permission_group_members (chat_id, group_id,
                     contact_id) VALUES (?, ?, ?)",
                    (chat_id, *group_id, *contact_id),
                )?;
            }
            Ok(())
        })
        .await?;

    context.emit_event(EventType::ChatModified(chat_id));
    chatlist_events::emit_chatlist_item_changed(context, chat_id);
    info!(context, "Applied chatroom permissions of {chat_id}.");
    Ok(())
}

/// Applies the permission groups which are received from another chat member.
///
/// The permission groups are only applied
/// if the sender may manage the permission groups of the chatroom.
/// If the chatroom has no permission groups yet,
/// e.g. because we have just been added to it,
/// the permission groups are applied unconditionally.
pub(crate) async fn apply_permissions_from_wire(
    context: &Context,
    chat_id: ChatId,
    from_id: ContactId,
    json: &str,
) -> Result<()> {
    if !chat_id.get_permission_groups(context).await?.is_empty()
        && !chat_id
            .has_permission(context, from_id, ChatPermission::ManagePermissionGroup)
            .await?
    {
        bail!("{from_id} may not manage the permission groups of {chat_id}")
    }
    apply_permissions(context, chat_id, json).await
}

/// Removes all permission group assignments
/// of a contact which was removed from the chatroom
/// and sends the updated permission groups to the other members.
pub(crate) async fn forget_contact(
    context: &Context,
    chat_id: ChatId,
    contact_id: ContactId,
) -> Result<()> {
    context
        .sql
        .execute(
            "DELETE FROM chatroom_permission_group_members WHERE chat_id=? AND contact_id=?",
            (chat_id, contact_id),
        )
        .await?;
    broadcast_permissions(context, chat_id, crate::sync::Sync::Sync).await?;
    Ok(())
}

/// Serializes the permission groups of the chatroom to JSON.
async fn serialize(context: &Context, chat_id: ChatId) -> Result<String> {
    let chat = Chat::load_from_db(context, chat_id).await?;
    let groups = chat_id.get_permission_groups(context).await?;

    let mut members = Vec::new();
    for group in &groups {
        for contact_id in chat_id
            .get_permission_group_members(context, group.id)
            .await?
        {
            if let Some(contact) = Contact::get_by_id_optional(context, contact_id).await? {
                members.push(MemberJson {
                    group_id: group.id,
                    addr: contact.get_addr().to_lowercase(),
                });
            }
        }
    }

    let creator = match chat.get_chatroom_creator(context).await? {
        Some(contact_id) => Contact::get_by_id(context, contact_id)
            .await?
            .get_addr()
            .to_lowercase(),
        None => String::new(),
    };

    let data = PermissionsJson {
        creator,
        groups: groups
            .iter()
            .map(|group| GroupJson {
                id: group.id,
                name: group.name.clone(),
                permissions: permissions_to_string(&group.permissions),
            })
            .collect(),
        members,
    };
    Ok(serde_json::to_string(&data)?)
}

/// Inserts a permission group, replacing an existing group with the same ID.
async fn insert_group(
    context: &Context,
    chat_id: ChatId,
    group_id: u32,
    name: &str,
    permissions: &[ChatPermission],
) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT OR REPLACE INTO chatroom_permission_groups (chat_id, id, name, permissions)
             VALUES (?, ?, ?, ?)",
            (chat_id, group_id, name, permissions_to_string(permissions)),
        )
        .await?;
    Ok(())
}

/// Assigns a permission group to a contact.
async fn insert_group_member(
    context: &Context,
    chat_id: ChatId,
    group_id: u32,
    contact_id: ContactId,
) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT OR IGNORE INTO chatroom_permission_group_members (chat_id, group_id, contact_id)
             VALUES (?, ?, ?)",
            (chat_id, group_id, contact_id),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod chatroom_tests;
