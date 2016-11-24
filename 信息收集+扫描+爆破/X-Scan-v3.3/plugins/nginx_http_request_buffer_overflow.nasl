#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if(description)
{
  script_id(41608);
  script_version ('$Revision: 1.4 $');

  script_cve_id( 'CVE-2009-2629' );
  script_bugtraq_id(36384,36839);
  script_xref(name:'CERT', value:'180065');
  script_xref(name: 'OSVDB', value: '58128');
  script_xref(name: 'OSVDB', value: '59278');

  script_name(english:'nginx HTTP Request Multiple Vulnerabilities');
  script_summary(english:'Checks version in Server response header');

  script_set_attribute(
    attribute:'synopsis',
    value: string(
      'The web server on the remote host is affected by multiple\n',
      'vulnerabilities.' )
  );
  script_set_attribute(
    attribute:'description',
    value:string(
      'The remote web server is running nginx, a lightweight, high performance\n',
      'web server / reverse proxy and e-mail (IMAP/POP3) proxy.\n',
      '\n',
      'According to its Server response header, the installed version of \n',
      'nginx is affected by multiple vulnerabilities :\n',
      '  - A remote buffer overflow attack related to its parsing\n',
      '    of complex URIs.\n',
      '\n',
      '  - A remote denial of service attack related to its parsing\n',
      '    of HTTP request headers.\n',
      '\n'
    )
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://nginx.net/CHANGES'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://nginx.net/CHANGES-0.7'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://nginx.net/CHANGES-0.6'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://nginx.net/CHANGES-0.5'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://sysoev.ru/nginx/patch.180065.txt'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/fulldisclosure/2009/Oct/306'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to version 0.8.15, 0.7.62, 0.6.39, 0.5.38, or later.'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_set_attribute( attribute:'patch_publication_date', value:'2009/09/14' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/09/24' );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Web Servers');

  script_copyright(english:'This script is Copyright (C) 2009 Tenable Network Security, Inc.');

  script_dependencie( 'http_version.nasl' );
  script_require_ports( 'Services/www', 80 );
  exit(0);
}

#
# The script code starts here
#

include( 'global_settings.inc' );
include("misc_func.inc");
include( 'http.inc' );

if (report_paranoia < 2) exit(1, "Security patches may have been backported.");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if (!banner) exit(1, "get_http_banner() returned NULL for port "+port+".");

if ( 'Server: nginx/0.' >!< banner ) exit( 0, "Server response header indicates it's not nginx." );

pat = "Server: nginx/0\.(5\.([0-9]|[1-2][0-9]|3[0-7])|" +
                        "6\.([0-9]|[1-2][0-9]|3[0-8])|" +
                        "7\.([0-9]|[1-5][0-9]|6[0-1])|" +
                        "8\.([0-9]|1[0-4]))" +
                        "([^0-9]|$)" ;

match = ( egrep(pattern:pat, string:banner ) );
if ( match )
{
  if (report_verbosity > 0 )
  {
    report = string(
      '\n',
      '  Product                : nginx HTTP Server\n',
      '  Server Response Header : ', match, '\n',
      '  Fix                    : 0.8.15, 0.7.62, 0.6.39, 0.5.38, or later\n'
    );
    security_hole( port:port, extra:report );
  }
  else security_hole( port );
}
