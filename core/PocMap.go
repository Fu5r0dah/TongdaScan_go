package core

import (
	"tongdascan_go/vulners"
)

func AddPoc(pocs map[string]interface{}) map[string]interface{} {
	pocs["Td01"] = &vulners.Td01{}
	pocs["Td02"] = &vulners.Td02{}
	pocs["Td03"] = &vulners.Td03{}
	pocs["Td04"] = &vulners.Td04{}
	pocs["Td05"] = &vulners.Td05{}
	pocs["Td06"] = &vulners.Td06{}
	pocs["Td07"] = &vulners.Td07{}
	pocs["Td08"] = &vulners.Td08{}
	pocs["Td09"] = &vulners.Td09{}
	pocs["Td10"] = &vulners.Td10{}
	pocs["Td11"] = &vulners.Td11{}
	return pocs
}
