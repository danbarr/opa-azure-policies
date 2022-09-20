package terraform.policies.azure.network_001

import future.keywords.in
import input.plan as tfplan

actions := [
	["no-op"],
	["create"],
	["update"],
]

invalid_cidrs := [
	"*",
	"0.0.0.0/0"
]

secure_ports := [
	"22",
	"3389"
]

resources := [resource_changes |
	resource_changes := tfplan.resource_changes[_]
	resource_changes.type == "azurerm_network_security_group"
	resource_changes.mode == "managed"
	resource_changes.change.actions in actions
]

violations := [resource |
	resource := resources[_]
	rules := resource.change.after.security_rule[_]
	rules.direction == "Inbound"
	rules.access == "Allow"
	rules.destination_port_range in secure_ports
	rules.source_address_prefix in invalid_cidrs
]

violators[address] {
	address := violations[_].address
}

# METADATA
# title: AZURE-NETWORK-001
# description: Ensure that network security groups don't allow unrestricted SSH or RDP
# custom:
#  severity: medium
#  enforcement_level: mandatory
# authors:
# - name: Dan Barr
# organizations:
# - HashiCorp
rule[result] {
	count(violations) != 0
	result := {
		"policy": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"severity": rego.metadata.rule().custom.severity,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"resources": {
			"count": count(violations),
			"addresses": violators,
		},
	}
}