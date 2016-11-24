# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-13.xml
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
 script_id(18520);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200506-13");
 script_cve_id("CVE-2005-1707");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-13
(webapp-config: Insecure temporary file handling)


    Eric Romang discovered webapp-config uses a predictable temporary
    filename while processing certain options, resulting in a race
    condition.
  
Impact

    Successful exploitation of the race condition would allow an attacker
    to disrupt the operation of webapp-config, or execute arbitrary shell
    commands with the privileges of the user running webapp-config. A local
    attacker could use a symlink attack to create or overwrite files with
    the permissions of the user running webapp-config.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All webapp-config users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/webapp-config-1.11"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1707');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-13] webapp-config: Insecure temporary file handling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'webapp-config: Insecure temporary file handling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/webapp-config", unaffected: make_list("ge 1.11"), vulnerable: make_list("lt 1.11")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
