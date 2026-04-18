package securestorage.authz

import rego.v1

default allow := false
default deny_reason := "Отказано в доступе"

roles := {r | some i; r := input.subject.roles[i]}

is_admin if {
  "admin" in roles
}

is_editor if {
  "editor" in roles
}

is_viewer if {
  "viewer" in roles
}

can_create_docs if {
  is_admin
}

can_create_docs if {
  is_editor
}

can_create_docs if {
  is_viewer
}

can_list_docs if {
  is_viewer
}

can_list_docs if {
  is_editor
}

can_list_nodes if {
  is_editor
}

can_list_nodes if {
  is_viewer
}

can_list_nodes if {
  is_admin
}

trusted_network if {
  some cidr in data.securestorage.trusted_networks
  net.cidr_contains(cidr, input.request.client_ip)
}


allow if {
  is_admin
}

allow if {
  input.action == "documents:create"
  can_create_docs
}

allow if {
  input.action == "documents:list"
  can_list_docs
}

allow if {
  input.action == "documents:view"
  is_admin
  trusted_network
}

allow if {
  input.action == "documents:view"
  trusted_network
}


allow if {
  input.action == "documents:download"
  trusted_network
}

allow if {
  input.action == "documents:update"
  is_editor
  trusted_network
}

allow if {
  input.action == "documents:delete"
  is_admin
}

allow if {
  input.action == "nodes:list"
  can_list_nodes
}

allow if {
  input.action == "nodes:create"
  is_admin
}

allow if {
  input.action == "nodes:check"
  is_admin
}

allow if {
  input.action == "nodes:delete"
  is_admin
}

deny_reason := "Вы можете просматривать документ, только из доверенной сети " if {
  input.action == "documents:view"
  not trusted_network
}

deny_reason := "Вы можете скачивать документs, только из доверенной сети " if {
  input.action == "documents:download"
  not trusted_network
}

deny_reason := "Вы можете изменять документ, только из доверенной сети " if {
  input.action == "documents:update"
  not trusted_network
}
