package terraform.policies.azure.compute_003

import future.keywords.in
import input.plan as tfplan

actions := [
	["no-op"],
	["create"],
	["update"],
]

resources := [resource_changes |
	resource_changes := tfplan.resource_changes[_]
	resource_changes.type == "azurerm_virtual_machine"
	resource_changes.mode == "managed"
	resource_changes.change.actions in actions
]

violations := [resource |
	resource := resources[_]
]

violators[address] {
	address := violations[_].address
}

# METADATA
# title: AZURE-COMPUTE-003
# description: Disallow the use of the legacy azurerm_virtual_machine resource
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