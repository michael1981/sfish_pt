#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11336);

 script_version("$Revision: 1.38 $");
 script_cve_id("CVE-2002-0616", "CVE-2002-0617", "CVE-2002-0618", "CVE-2002-0619");
 script_bugtraq_id(4821, 5063, 5064, 5066);
 script_xref(name:"OSVDB", value:"5171");
 script_xref(name:"OSVDB", value:"5173");
 script_xref(name:"OSVDB", value:"5174");
 script_xref(name:"OSVDB", value:"5175");

 script_name(english:"MS02-031: Cumulative patches for Excel and Word for Windows (324458)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Excel." );
 script_set_attribute(attribute:"description", value:
"The remote host has old versions of Word and Excel installed.  An
attacker may use these to execute arbitrary code on this host. 

To succeed, the attacker would have to send a rogue Excel or Word file
to a user on this computer and have him open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-031.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the version of WinWord.exe and Excel.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


rootfile = hotfix_get_officeprogramfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);

product_file["Word"] = "WinWord.exe";
product_file["WordCnv"] = "Wordcnv.exe";
product_file["WordViewer"] = "Wordview.exe";
product_file["Excel"] = "Excel.exe";
product_file["ExcelCnv"] = "Excelcnv.exe";
product_file["ExcelViewer"] = "Xlview.exe";
product_file["PowerPoint"] = "PowerPnt.exe";
product_file["PowerPointViewer"] = "Pptview.exe";
product_file["PowerPointCnv"] = "Ppcnvcom.exe";
product_file["Publisher"] = "Mspub.exe";
product_file["Project"] = "WinProj.exe";
product_file["OneNote"] = "OneNote.exe";

products = make_list("Word", "WordCnv", "WordViewer", "Excel", "ExcelCnv", "ExcelViewer", "PowerPoint", "PowerPointViewer", "PowerPointCnv", "Publisher", "Project", "OneNote");
paths = make_list("Office12", "Office11", "Office10", "Office", "PowerPoint Viewer");


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

foreach product (products)
{
 foreach path (paths)
 {
  file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\" + path + "\" + product_file[product], string:rootfile);

  handle =  CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( ! isnull(handle) )
  {
   v =  GetFileVersion(handle:handle);
   CloseFile(handle:handle);
   if ( ! isnull(v) ) 
   {
    product_path = string(rootfile, "\\Microsoft Office\\", path, "\\", product_file[product]);
    set_kb_item(name:"SMB/Office/" + product + "/ProductPath", value:product_path);

    set_kb_item(name:"SMB/Office/" + product + "/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));
    break;
   }
  }
 }
}


NetUseDel();

excel_version = get_kb_item("SMB/Office/Excel/Version");
word_version = get_kb_item("SMB/Office/Excel/Version");

if ( ! isnull(excel_version) ) 
{
 if ( excel_version[0] == 9 && excel_version[1] == 0 && excel_version[2] == 0 && excel_version[3] < 6508 ) 
 {
	 {
 set_kb_item(name:"SMB/Missing/MS02-031", value:TRUE);
 hotfix_security_hole();
 }
	exit(0);
 }
 else if ( excel_version[0] == 10 && excel_version[1] == 0 && excel_version[2] < 4109 ) 
 {
	 {
 set_kb_item(name:"SMB/Missing/MS02-031", value:TRUE);
 hotfix_security_hole();
 }
	exit(0);
 }
}

if ( ! isnull(word_version) ) 
{
 if ( word_version[0] == 10 && word_version[1] == 0 && ( word_version[2] < 4009 || (word_version[2] == 4009 && word_version[3] < 3501)) ) 
 {
	 {
 set_kb_item(name:"SMB/Missing/MS02-031", value:TRUE);
 hotfix_security_hole();
 }
	exit(0);
 }
}
