; =============================================================================
; SecureSeaHorse SIEM v3.0.0 -- Windows Installer (NSIS)
; =============================================================================
; Build: makensis installer_windows.nsi
; Requires: NSIS 3.x (https://nsis.sourceforge.io)
; =============================================================================

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define PRODUCT_NAME "SecureSeaHorse SIEM"
!define PRODUCT_VERSION "3.0.0"
!define PRODUCT_PUBLISHER "SecureSeaHorse Project"
!define INSTALL_DIR "$PROGRAMFILES\SecureSeaHorse"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "SecureSeaHorse-v3.0.0-Setup.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Welcome to ${PRODUCT_NAME} Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will install SecureSeaHorse SIEM v${PRODUCT_VERSION}.$\n$\nYou can install the Server, Client, or both.$\n$\nClick Next to continue."

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "SIEM Server" SEC_SERVER
    SetOutPath "$INSTDIR\server"
    File /oname=seahorse-server.exe "build\SeaHorseServer.exe"

    SetOutPath "$INSTDIR\server\config"
    File "config\server.conf"
    File "config\rules.conf"

    CreateDirectory "$INSTDIR\server\config\feeds"
    CreateDirectory "$INSTDIR\server\certs"
    CreateDirectory "$INSTDIR\server\scripts"
    CreateDirectory "$INSTDIR\server\logs"

    nsExec::ExecToLog 'sc create SeaHorseServer binPath= "$INSTDIR\server\seahorse-server.exe --config $INSTDIR\server\config\server.conf" start= auto DisplayName= "SecureSeaHorse SIEM Server"'
    nsExec::ExecToLog 'sc description SeaHorseServer "SecureSeaHorse SIEM Server - Security monitoring and threat detection"'
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="SeaHorse Server TLS" dir=in action=allow protocol=TCP localport=9443'
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="SeaHorse Dashboard" dir=in action=allow protocol=TCP localport=8080'

    WriteUninstaller "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "${PRODUCT_NAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "Publisher" "${PRODUCT_PUBLISHER}"

    CreateDirectory "$SMPROGRAMS\SecureSeaHorse"
    CreateShortCut "$SMPROGRAMS\SecureSeaHorse\Dashboard.lnk" "http://localhost:8080"
    CreateShortCut "$SMPROGRAMS\SecureSeaHorse\Server Config.lnk" "$INSTDIR\server\config\server.conf"
    CreateShortCut "$SMPROGRAMS\SecureSeaHorse\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section "SIEM Client Agent" SEC_CLIENT
    SetOutPath "$INSTDIR\client"
    File /oname=seahorse-client.exe "build\SeaHorseClient.exe"

    SetOutPath "$INSTDIR\client\config"
    File "config\client.conf"

    CreateDirectory "$INSTDIR\client\certs"
    CreateDirectory "$INSTDIR\client\logs"

    nsExec::ExecToLog 'sc create SeaHorseClient binPath= "$INSTDIR\client\seahorse-client.exe --config $INSTDIR\client\config\client.conf" start= auto DisplayName= "SecureSeaHorse SIEM Agent"'
    nsExec::ExecToLog 'sc description SeaHorseClient "SecureSeaHorse SIEM Agent - Endpoint monitoring and telemetry"'
SectionEnd

Section /o "Source Code" SEC_SOURCE
    SetOutPath "$INSTDIR\src\server"
    File /r "src\server\*.*"
    SetOutPath "$INSTDIR\src\client"
    File /r "src\client\*.*"
    SetOutPath "$INSTDIR"
    File "CMakeLists.txt"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_SERVER} "SIEM server with REST API dashboard, threat detection, and incident response."
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_CLIENT} "Endpoint agent that monitors processes, connections, files, and sends telemetry."
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_SOURCE} "Full C++ source code for building from source."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
    nsExec::ExecToLog 'sc stop SeaHorseServer'
    nsExec::ExecToLog 'sc stop SeaHorseClient'
    nsExec::ExecToLog 'sc delete SeaHorseServer'
    nsExec::ExecToLog 'sc delete SeaHorseClient'
    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="SeaHorse Server TLS"'
    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="SeaHorse Dashboard"'
    RMDir /r "$INSTDIR"
    RMDir /r "$SMPROGRAMS\SecureSeaHorse"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
SectionEnd
