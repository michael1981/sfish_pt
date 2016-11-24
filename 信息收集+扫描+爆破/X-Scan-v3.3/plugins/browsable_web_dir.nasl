#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40984);
 script_version ("$Revision: 1.1 $");

 script_name(english:"Browsable Web Directories");
 script_summary(english:"Display all browsable web directories");
 
 script_set_attribute(attribute:"synopsis", value:
"Some directories on the remote web server are browsable." );
 script_set_attribute(attribute:"description", value:
"Miscellaneous Nessus plugins identified directories on this web
server that are browsable." );
 script_set_attribute(attribute:"solution", value:
"Make sure that browsable directories do not leak confidential
informative or give access to sensitive resources.  And use access
restrictions or disable directory indexing for any that do." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value:
"2009/09/15");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl", "doc_browsable.nasl", "apache_dir_listing.nasl", "cgibin_browsable.nasl", "doc_package_browseable.nasl", "netbeans.nasl", "perl_browseable.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

port = get_http_port(default:80, embedded: 1);

dirs = get_kb_list('www/'+port+'/content/directory_index');
if (isnull(dirs)) exit(0);
dirs = make_list(dirs);
report  = '';

foreach d (dirs) report = strcat(report, d, '\n');
if (report == '') exit(0);
report = strcat('\nThe following directories are browsable :\n\n', report);
security_note(port: port, extra: report);
if (COMMAND_LINE) display(report);

