package terraform.policies.azure.compute_001

import future.keywords.in
import input.plan as tfplan

actions := [
	["no-op"],
	["create"],
	["update"],
]

types := [
	"Standard_A1_v2",
	"Standard_A2_v2",
	"Standard_B2s"
]

resources := [resource_changes |
	resource_changes := tfplan.resource_changes[_]
	resource_changes.type == "azurerm_linux_virtual_machine"
	resource_changes.mode == "managed"
	resource_changes.change.actions in actions
]

violations := [resource |
	resource := resources[_]
	not resource.change.after.size in types
]

violators[address] {
	address := violations[_].address
}

# METADATA
# title: AZURE-COMPUTE-001
# description: Ensure only allowed VM size values are defined
# custom:
#  severity: low
#  enforcement_level: advisory
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
