# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-28.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(24313);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-28");
 script_cve_id("CVE-2007-0664");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-28
(thttpd: Unauthenticated remote file access)


    thttpd is vulnerable to an underlying change made to the
    start-stop-daemon command in the current stable Gentoo baselayout
    package (version 1.12.6). In the new version, the start-stop-daemon
    command performs a "chdir /" command just before starting the thttpd
    process. In the Gentoo default configuration, this causes thttpd to
    start with the document root set to "/", the sytem root directory.
  
Impact

    When thttpd starts with the document root set to the system root
    directory, all files on the system that are readable by the thttpd
    process can be remotely accessed by unauthenticated users.
  
Workaround

    Alter the THTTPD_OPTS variable in /etc/conf.d/thttpd to include the
    "-d" option to specify the document root. Alternatively, modify the
    THTTPD_OPTS variable in /etc/conf.d/thttpd to specify a thttpd.conf
    file using the "-C" option, and then configure the "dir=" directive in
    that thttpd.conf file.
  
');
script_set_attribute(attribute:'solution', value: '
    All thttpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/thttpd-2.25b-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0664');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-28] thttpd: Unauthenticated remote file access');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'thttpd: Unauthenticated remote file access');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/thttpd", unaffected: make_list("ge 2.25b-r6"), vulnerable: make_list("lt 2.25b-r6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
