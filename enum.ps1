function Write-Title{
    param([String]$Title)
    $splush = "`n" * 2 + ("#" * 50) + "`n" + "#" * [Math]::Floor((50 - $Title.Length - 2) / 2) + " "+ $Title + " " + "#" * [Math]::Ceiling((50 - $Title.Length - 2) / 2) + "`n" + ("#" * 50) + "`n"
    Write-Host -ForegroundColor Green $splush
}

function Enum-SystemInfo {
    Write-Title $MyInvocation.MyCommand.Name
    systeminfo
}

function Enum-UserInfo {
    Write-Title $MyInvocation.MyCommand.Name
    whoami /all
}

function Enum-LocalUsers {
    Write-Title $MyInvocation.MyCommand.Name
    $NonInterestingUserName = "Administrator,DefaultAccount,Guest,WDAGUtilityAccount"
    Get-LocalUser | Write-Host
}

function Enum-LocalGroups {
    Write-Title $MyInvocation.MyCommand.Name
    $GroupMembers = @{}
    Get-LocalGroup | ForEach-Object {
      $GroupMembers.add($_, (Get-LocalGroupMember $_))
    }
    $GroupMembers
}

function Enum-NetworkInfo {
    Write-Title $MyInvocation.MyCommand.Name
    #ipconfig /all
    #arp -a
    #route print
    Write-Host -ForegroundColor Yellow "`nIP address"
    Get-NetIPAddress | ForEach-Object { $_.IPAddress }
    Write-Host -ForegroundColor Yellow "`nListening ports" 
    Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalAddress,LocalPort,State | Sort-Object LocalPort | ft 
}

function Enum-InterestingFile {
    Write-Title $MyInvocation.MyCommand.Name
    $Path = "C:\"
    $Include = @("*.txt","*.kdbx","*.pdf","*.xls","*.xlsx","*.doc","*.docx","*.config","*.ini","*.cnf")
    $Exclude = @("C:\Program Files\*","C:\Program Files (x86)\*","C:\Program Data\*","C:\Windows\*")
    Get-ChildItem -Path $Path -Directory -Recurse -ErrorAction SilentlyContinue |`
    Where-Object {
      $_.FullName -inotmatch "C:\\(Program Files|Windows|Program Files|Program Files \(x86\)|PerfLogs).*"
    } | ForEach-Object {
      #Get-ChildItem -Path $_.FullName -File -Include $Include -ErrorAction SilentlyContinue | Write-Host
      $FilePath = $_.FullName + "\*"
      Get-ChildItem -Path $FilePath -File -Include $Include -ErrorAction SilentlyContinue | Write-Host
    }

    $SysPrepFiles = @("C:\unattend.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml","C:\Windows\system32\sysprep.inf","C:\Windows\system32\sysprep\sysprep.xml")
    $SysPrepFiles | ForEach-Object {
        if(Test-Path $_) { Get-Content $_ }
    }
}

function Enum-Service {
    Write-Title $MyInvocation.MyCommand.Name
    $NonInterestingService = @("ActiveXInstaller(AxInstSV)","AgentActivationRuntime_2ccb4","AllJoynRouterService","AppReadiness","ApplicationIdentity","ApplicationInformation","ApplicationLayerGatewayService","ApplicationManagement","AppXDeploymentService(AppXSVC)","AssignedAccessManagerService","AutoTimeZoneUpdater","AVCTPservice","BackgroundIntelligentTransferService","BackgroundTasksInfrastructureService","BaseFilteringEngine","BitLockerDriveEncryptionService","BlockLevelBackupEngineService","BluetoothAudioGatewayService","BluetoothSupportService","BluetoothUserSupportService_2ccb4","BranchCache","CapabilityAccessManagerService","CaptureService_2ccb4","CellularTime","CertificatePropagation","ClientLicenseService(ClipSVC)","ClipboardUserService_2ccb4","CNGKeyIsolation","COM+EventSystem","COM+SystemApplication","ConnectedDevicesPlatformService","ConnectedDevicesPlatformUserService_2ccb4","ConnectedUserExperiencesandTelemetry","ConsentUX_2ccb4","ContactData_2ccb4","CoreMessaging","CredentialManager","CredentialEnrollmentManagerUserSvc_2ccb4","CryptographicServices","DataSharingService","DataUsage","DCOMServerProcessLauncher","DeliveryOptimization","DeviceAssociationService","DeviceInstallService","DeviceManagementEnrollmentService","DeviceManagementWirelessApplicationProtocol(WAP)PushmessageRoutingService","DeviceSetupManager","DeviceAssociationBroker_2ccb4","DevicePicker_2ccb4","DevicesFlow_2ccb4","DevQueryBackgroundDiscoveryBroker","DHCPClient","DiagnosticExecutionService","DiagnosticPolicyService","DiagnosticServiceHost","DiagnosticSystemHost","DisplayEnhancementService","DisplayPolicyService","DistributedLinkTrackingClient","DistributedTransactionCoordinator","DNSClient","DownloadedMapsManager","EmbeddedMode","EncryptingFileSystem(EFS)","EnterpriseAppManagementService","ExtensibleAuthenticationProtocol","Fax","FileHistoryService","FunctionDiscoveryProviderHost","FunctionDiscoveryResourcePublication","GameDVRandBroadcastUserService_2ccb4","GeolocationService","GraphicsPerfSvc","GroupPolicyClient","HumanInterfaceDeviceService","HVHostService","Hyper-VDataExchangeService","Hyper-VGuestServiceInterface","Hyper-VGuestShutdownService","Hyper-VHeartbeatService","Hyper-VPowerShellDirectService","Hyper-VRemoteDesktopVirtualizationService","Hyper-VTimeSynchronizationService","Hyper-VVolumeShadowCopyRequestor","IKEandAuthIPIPsecKeyingModules","InternetConnectionSharing(ICS)","IPHelper","IPTranslationConfigurationService","IPsecPolicyAgent","KtmRmforDistributedTransactionCoordinator","LanguageExperienceService","Link-LayerTopologyDiscoveryMapper","LocalProfileAssistantService","LocalSessionManager","MessagingService_2ccb4","Microsoft(R)DiagnosticsHubStandardCollectorService","MicrosoftAccountSign-inAssistant","MicrosoftApp-VClient","MicrosoftDefenderAntivirusNetworkInspectionService","MicrosoftDefenderAntivirusService","MicrosoftEdgeElevationService(MicrosoftEdgeElevationService)","MicrosoftEdgeUpdateService(edgeupdate)","MicrosoftEdgeUpdateService(edgeupdatem)","MicrosoftiSCSIInitiatorService","MicrosoftPassport","MicrosoftPassportContainer","MicrosoftSoftwareShadowCopyProvider","MicrosoftStorageSpacesSMP","MicrosoftStoreInstallService","MicrosoftWindowsSMSRouterService.","NaturalAuthentication","Net.TcpPortSharingService","Netlogon","NetworkConnectedDevicesAuto-Setup","NetworkConnectionBroker","NetworkConnections","NetworkConnectivityAssistant","NetworkListService","NetworkLocationAwareness","NetworkSetupService","NetworkStoreInterfaceService","OfflineFiles","OpenSSHAuthenticationAgent","Optimizedrives","ParentalControls","PaymentsandNFC/SEManager","PeerNameResolutionProtocol","PeerNetworkingGrouping","PeerNetworkingIdentityManager","PerformanceCounterDLLHost","PerformanceLogs&amp;Alerts","PhoneService","PlugandPlay","PNRPMachineNamePublicationService","PortableDeviceEnumeratorService","Power","PrintSpooler","PrinterExtensionsandNotifications","PrintWorkflow_2ccb4","ProblemReportsControlPanelSupport","ProgramCompatibilityAssistantService","QualityWindowsAudioVideoExperience","RadioManagementService","RecommendedTroubleshootingService","RemoteAccessAutoConnectionManager","RemoteAccessConnectionManager","RemoteDesktopConfiguration","RemoteDesktopServices","RemoteDesktopServicesUserModePortRedirector","RemoteProcedureCall(RPC)","RemoteProcedureCall(RPC)Locator","RemoteRegistry","RetailDemoService","RoutingandRemoteAccess","RPCEndpointMapper","SecondaryLogon","SecureSocketTunnelingProtocolService","SecurityAccountsManager","SecurityCenter","SensorDataService","SensorMonitoringService","SensorService","Server","SharedPCAccountManager","ShellHardwareDetection","SmartCard","SmartCardDeviceEnumerationService","SmartCardRemovalPolicy","SNMPTrap","SoftwareProtection","SpatialDataService","SpotVerifier","SSDPDiscovery","StateRepositoryService","StillImageAcquisitionEvents","StorageService","StorageTiersManagement","SyncHost_2ccb4","SysMain","SystemEventNotificationService","SystemEventsBroker","SystemGuardRuntimeMonitorBroker","TaskScheduler","TCP/IPNetBIOSHelper","Telephony","Themes","TimeBroker","TouchKeyboardandHandwritingPanelService","UdkUserService_2ccb4","UpdateOrchestratorService","UPnPDeviceHost","UserDataAccess_2ccb4","UserDataStorage_2ccb4","UserExperienceVirtualizationService","UserManager","UserProfileService","VirtualDisk","VirtualBoxGuestAdditionsService","VolumeShadowCopy","VolumetricAudioCompositorService","WalletService","WarpJITSvc","WebAccountManager","WebClient","Wi-FiDirectServicesConnectionManagerService","WindowsAudio","WindowsAudioEndpointBuilder","WindowsBackupWindowsBiometricService","WindowsCameraFrameServer","WindowsConnectNow-ConfigRegistrar","WindowsConnectionManager","WindowsDefenderAdvancedThreatProtectionService","WindowsDefenderFirewall","WindowsEncryptionProviderHostService","WindowsErrorReportingService","WindowsEventCollector","WindowsEventLog","WindowsFontCacheService","WindowsImageAcquisition(WIA)","WindowsInsiderService","WindowsInstaller","WindowsLicenseManagerService","WindowsManagementInstrumentation","WindowsManagementService","WindowsMediaPlayerNetworkSharingService","WindowsMixedRealityOpenXRService","WindowsMobileHotspotService","WindowsModulesInstaller","WindowsPerceptionService","WindowsPerceptionSimulationService","WindowsPushNotificationsSystemService","WindowsPushNotificationsUserService_2ccb4","WindowsPushToInstallService","WindowsRemoteManagement(WS-Management)","WindowsSearch","WindowsSecurityService","WindowsTime","WindowsUpdate","WindowsUpdateMedicService","WinHTTPWebProxyAuto-DiscoveryService","WiredAutoConfig","WLANAutoConfig","WMIPerformanceAdapter","WorkFolders","Workstation","WWANAutoConfig","XboxAccessoryManagementService","XboxLiveAuthManager","XboxLiveGameSave","XboxLiveNetworkingService")
    Get-Service | ForEach-Object {
        if($NonInterestingService -inotcontains $_.DisplayName.Replace(" ","")) {
            Write-Host $_
        }
    }
}

function Enum-Env {
    Write-Title $MyInvocation.MyCommand.Name
    Get-ChildItem Env: | ft Key,Value
}

function Enum-InstalledSoftware {
    Write-Title $MyInvocation.MyCommand.Name
    Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
}

function Enum-PowerShellHistory {
    Write-Title $MyInvocation.MyCommand.Name
    if(Test-Path (Get-PSReadlineOption).HistorySavePath) {
        Get-Content (Get-PSReadlineOption).HistorySavePath
    }
}

function Enum-PasswordFromRegistry {
    Get-ChildItem "HKCU:\Software\ORL\WinVNC3\Password" -ErrorAction SilentlyContinue
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" -ErrorAction SilentlyContinue
    Get-ChildItem "HKLM:\SYSTEM\Current\ControlSet\Services\SNMP" -ErrorAction SilentlyContinue
    Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" -ErrorAction SilentlyContinue
}

function Invoke-AllChecks {
    Enum-SystemInfo
    Enum-UserInfo
    Enum-LocalUsers
    Enum-LocalGroups
    Enum-NetworkInfo
    Enum-InterestingFile
    Enum-Service
    Enum-Env
    Enum-PowerShellHistory
    Enum-InstalledSoftware
}
