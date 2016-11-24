#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# smb_hotfixes.inc
# $Revision: 1.35 $


include("global_settings.inc");

function hotfix_check_exchange_installed()
{
 local_var vers;

 vers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Exchange/Setup/ServicePackBuild");
 if ( ! vers )
	return NULL;
 else
	return vers;
}

function hotfix_data_access_version()
{
 local_var vers;

 vers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DataAccess/Version");
 if ( ! vers )
	return NULL;
 else
	return vers;
}

#
# Returns Office version if it is installed, NULL if it is not
#
function hotfix_check_office_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Outlook");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/Word");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/WordViewer");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/Excel");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/ExcelViewer");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/Powerpoint");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/Publisher");
 if ( flag )
   return flag;

 return NULL;
}


#
# Returns Word version if it is installed, NULL if it is not
#
function hotfix_check_word_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Word");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Excel version if it is installed, NULL if it is not
#
function hotfix_check_excel_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Excel");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Powerpoint version if it is installed, NULL if it is not
#
function hotfix_check_powerpoint_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Powerpoint");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Publisher version if it is installed, NULL if it is not
#
function hotfix_check_publisher_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Publisher");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Outlook version if it is installed, NULL if it is not
#
function hotfix_check_outlook_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Outlook");
 if ( flag )
   return flag;

 return NULL;
}


function hotfix_check_ie_version()
{
 local_var flag;

 flag = get_kb_item("SMB/IE/Version");
 if ( flag )
   return flag;

 return NULL;
}

function hotfix_ie_gt()
{
 local_var vers;

 vers = hotfix_check_ie_version();
 if ( vers == NULL ) return -1;

 if ( ereg(pattern:strcat("^", _FCT_ANON_ARGS[0]), string:vers) )
	return 1;
 else
	return 0;
}


#
# Returns 1 if Works is installed, 0 if it is not
#
function hotfix_check_works_installed()
{
 local_var flag;

 flag = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Works");
 if ( ! flag )
	return 0;
 else
	return 1;
}



#
# Returns 1 if IIS is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_iis_installed()
{
 local_var w3svc;

 w3svc = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/W3SVC/ImagePath");
 if ( ! w3svc ) return -1;
 if ( "inetinfo" >!< w3svc && "iis" >!< w3svc )
	return 0;
 else
	return 1;
}

#
# Returns 1 if WINS is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_wins_installed()
{
 local_var wins;

 wins = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName");
 if ( ! wins ) return -1;
 else
	return 1;
}

# Returns 1 if a DHCP server is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_dhcpserver_installed()
{

 local_var dhcp;
 dhcp = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DHCPServer");
 if ( ! dhcp ) return -1;
 else
	return 1;
}

function hotfix_check_nt_server()
{
 local_var product_options;
 product_options = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions");
 if ( ! product_options ) return -1;
 if ("WinNT" >< product_options )
	return 0;
 else
	return 1;
}

function hotfix_check_domain_controler()
{
 local_var product_options;
 product_options = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions");
 if ( ! product_options ) return -1;
 if ("LanmanNT" >< product_options )
	return 1;
 else
	return 0;
}

#-----------------------------------------------------------------------------
# hotfix_check_server_core()
#
# Returns:
# -1 : could not determine whether it's Server Core.
#  0 : it's not Server Core.
#  1 : it is Server Core.
#-----------------------------------------------------------------------------

function hotfix_check_server_core()
{
 local_var ie, shell, version;

 # Server Core is only an option for Windows 2008.
 version = get_kb_item("SMB/WindowsVersion");
 if (!version) return -1;

 if ("6.0" >!< version) return 0;

 # Server Core doesn't have IE.
 ie = get_kb_item("SMB/IE/Version");
 if (!isnull(ie)) return 0;

 # Server Core doesn't have Windows Shell.
 #
 # nb: the following is the default shell in Server Core, although some
 #     people may tweak the setting, removing
 #     "runonce.exe /AlternateShellStartup".
 #
 #  cmd.exe /c "cd /d "%USERPROFILE%" & start cmd.exe /k runonce.exe /AlternateShellStartup"
 shell = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/Shell");
 if (!shell) return -1;

 if ("explorer.exe" >< tolower(shell)) return 0;
 if ("cmd.exe /c" >< shell && "start cmd.exe" >< shell)
	return 1;
 else
	return 0;
}

function hotfix_get_mssqldir()
{
 return get_kb_item("MSSQL/Path");
}

function hotfix_get_programfilesdir()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir");
 return str;
}

function hotfix_get_programfilesdirx86()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDirx86");
 return str;
}


function hotfix_get_commonfilesdir()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/CommonFilesDir");
 return str;
}

function hotfix_get_officeprogramfilesdir()
{
 local_var str, office_products, product;

 office_products = make_list("Outlook", "Word", "WordViewer", "Excel", "ExcelViewer", "Powerpoint", "Publisher");

 foreach product (office_products)
 {
  str = get_kb_item("SMB/Office/"+product+"/Path");
  if (str)
  {
   if ("Microsoft Office" >< str)
   {
    str = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1", string:str);
    return str;
   }
  }
 }

 return hotfix_get_programfilesdir();
}

function hotfix_get_officecommonfilesdir()
{
 local_var str, office_products, product;

 office_products = make_list("Outlook", "Word", "WordViewer", "Excel", "ExcelViewer", "Powerpoint", "Publisher");

 foreach product (office_products)
 {
  str = get_kb_item("SMB/Office/"+product+"/Path");
  if (str)
  {
   if ("Microsoft Office" >< str)
   {
    str = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1\Common Files", string:str);
    return str;
   }
  }
 }

 return hotfix_get_commonfilesdir();
}

function hotfix_get_systemroot()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot");
 return str;
}

function hotfix_check_sp(nt, win2k, xp, win2003, vista, win2008, win7)
{
  local_var vers, sp;

  vers = get_kb_item("SMB/WindowsVersion");
  if ( ! vers ) return -1;

  if ( nt &&  "4.0" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < nt )
 	return 1;
    else
	return 0;
  }
  else if ( win2k &&  "5.0" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;
    if ( sp < win2k )
 	return 1;
    else
	return 0;
  }
  else if ( xp &&  "5.1" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;
    if ( sp < xp )
 	return 1;
    else
	return 0;
  }
  else if ( win2003 &&  "5.2" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < win2003 )
 	return 1;
    else
	return 0;
  }
  else if ( vista &&  "6.0" >< vers)
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < vista )
 	return 1;
    else
	return 0;
  }
  else if ( win7 &&  "6.1" >< vers)
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < win7 )
 	return 1;
    else
	return 0;
  }

  return -1;
}

#-----------------------------------------------------------------------------
# hotfix_missing()
#
# Returns:
# -1 : Could not verify if the hotfix is installed (ie: lack of credentials)
#  0 : The hotfix is installed
#  1 : The hotfix is missing
#-----------------------------------------------------------------------------

function hotfix_missing(name)
{
 # KB test are disabled.
 return -1;
}
