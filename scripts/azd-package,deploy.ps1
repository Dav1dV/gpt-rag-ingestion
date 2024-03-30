Set-PSDebug -Trace 2

azd package

if ($?) {
	azd deploy
}

Set-PSDebug -Off
