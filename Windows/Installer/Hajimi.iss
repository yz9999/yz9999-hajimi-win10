; ============================================================================
; 哈基米 (Hajimi) Windows Dual-Architecture Installer (Inno Setup 6.x)
; Supports x64 (`-DMyArch=x64`) and ARM64 (`-DMyArch=arm64`)
; Cleanly stops running `Hajimi.exe` & `HajimiHelperService.exe` prior to
; over-the-top upgrades (`PrepareToInstall`) so `wintun.dll` / `HajimiEngine.dll`
; are never locked during file replacement.
; ============================================================================

#ifndef MyAppVersion
  #define MyAppVersion "0.2.1"
#endif
#ifndef MyArch
  #define MyArch "x64"
#endif
#ifndef StageDir
  #define StageDir "..\..\dist\hajimi-win-" + MyArch
#endif

[Setup]
AppId={{68616A69-6D69-4150-9A01-8899AABBCCDD}
AppName=哈基米 (Hajimi)
AppVersion={#MyAppVersion}
AppPublisher=Hajimi Project
DefaultDirName={autopf}\Hajimi
DefaultGroupName=哈基米 (Hajimi)
UninstallDisplayIcon={app}\Hajimi.exe
SetupIconFile=..\..\Resources\Hajimi.ico
CloseApplications=force
RestartApplications=no
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0.19044
#if MyArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif
OutputDir=..\..\dist
OutputBaseFilename=Hajimi-v{#MyAppVersion}-win-{#MyArch}-setup

[Languages]
#if FileExists(AddBackslash(CompilerPath) + "Languages\ChineseSimplified.isl")
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
#elif FileExists(SourcePath + "ChineseSimplified.isl")
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"
#endif
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\哈基米 (Hajimi)"; Filename: "{app}\Hajimi.exe"
Name: "{autodesktop}\哈基米 (Hajimi)"; Filename: "{app}\Hajimi.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\HajimiHelperService.exe"; Parameters: "--install"; StatusMsg: "正在注册零信任网络守护服务 (HajimiHelperService)..."; Flags: runhidden waituntilterminated
Filename: "{app}\Hajimi.exe"; Description: "{cm:LaunchProgram,哈基米 (Hajimi)}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/F /IM Hajimi.exe"; Flags: runhidden; RunOnceId: "StopHajimiGui"
Filename: "{app}\HajimiHelperService.exe"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveHajimiService"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  ExistingHelper: String;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Hajimi.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  ExistingHelper := ExpandConstant('{app}\HajimiHelperService.exe');
  if FileExists(ExistingHelper) then
  begin
    Exec(ExistingHelper, '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(300);
  end;
end;
