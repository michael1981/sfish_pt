#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11419);
 script_version ("$Revision: 1.16 $");
 
 script_name(english:"Web Server Office File Inventory");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts office-related files." );
 script_set_attribute(attribute:"description", value:
"This plugin connects to the remote web server and attempts to find
office-related files such as .doc, .ppt, .xls, .pdf etc." );
 script_set_attribute(attribute:"solution", value:
"Make sure that such files do not contain any confidential or otherwise
sensitive information and that they are only accessible to those with
valid credentials." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 script_summary(english:"Displays office files");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "webmirror.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


function test_files(files)
{
 local_var f, req, soc, r, retf;
 global_var port;
 
 retf = make_list();
 foreach f (files)
 {
  req = http_get(item:f, port:port);
  soc = http_open_socket(port);
 
  if(!soc)exit(0);
  
  send(socket:soc, data:req);
  r  = recv_line(socket:soc, length:4096);
  close(soc);
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:r)){
  	retf = make_list(retf, f);
	}
 }
 return retf;
}


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

report = "";

software["doc"] = "Word";
software["docx"] = "Word 2007";
software["docm"] = "Word 2007";
software["dotx"] = "Word 2007";
software["dotm"] = "Word 2007";
software["dot"] = "Word 2007";
software["xls"] = "Excel";
software["xlsx"] = "Excel 2007";
software["xlsm"] = "Excel 2007";
software["xlsb"] = "Excel 2007";
software["xltx"] = "Excel 2007";
software["xltm"] = "Excel 2007";
software["xlt"] = "Excel 2007";
software["xlam"] = "Excel 2007";
software["xla"] = "Excel 2007";
software["xps"] = "Excel 2007";
software["ppt"] = "PowerPoint";
software["pptx"] = "PowerPoint 2007";
software["pptm"] = "PowerPoint 2007";
software["potx"] = "PowerPoint 2007";
software["potm"] = "PowerPoint 2007";
software["pot"] = "PowerPoint 2007";
software["ppsx"] = "PowerPoint 2007";
software["ppsm"] = "PowerPoint 2007";
software["pps"] = "PowerPoint 2007";
software["ppam"] = "PowerPoint 2007";
software["ppa"] = "PowerPoint 2007";
software["wps"] = "MS Works";
software["wri"] = "Write";
software["csv"] = "CSV Spreadsheet";
software["dif"] = "DIF Spreadsheet";
software["rtf"] = "Rich Text Format / Word Processor";
software["pdf"] = "Adobe Acrobat";
software["sxw"] = "OO Writer";
software["sxi"] = "00 Presentation";
software["sxc"] = "00 Spreadsheet";
software["sdw"] = "StarWriter";
software["sdd"] = "StarImpress";
software["sdc"] = "StarCalc";
software["ods"] = "OpenDocument Spreadsheet";
software["odt"] = "OpenDocument Text";
software["odp"] = "OpenDocument Presentation";
software["odc"] = "OpenDocument";


foreach ext(keys(software))
{
 t = get_kb_list(string("www/", port, "/content/extensions/", ext));
if(!isnull(t)){
 t = test_files(files:make_list(t));
 word = NULL;
 foreach f (t)
 {
  word += '    ' + f + '\n';
 }
 if(word)
  report += '  - ' + software[ext] + ' files (.' + ext + ') :\n' + word + '\n';
 }
}

if (report)
{
 if (report_verbosity)
 {
  report = string(
    "\n",
    "The following office-related files are available on the remote server :\n",
    "\n",
    report
  );
  security_note(port:port, extra:report);
 }
 else security_note(port);
}
