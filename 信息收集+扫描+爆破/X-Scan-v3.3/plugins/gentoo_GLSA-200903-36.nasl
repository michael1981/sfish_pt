# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-36.xml
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
 script_id(36002);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-36");
 script_cve_id("CVE-2009-0753");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-36 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-36
(MLDonkey: Information disclosure)


    Michael Peselnik reported that src/utils/lib/url.ml in the web
    interface of MLDonkey does not handle file names with leading double
    slashes properly.
  
Impact

    A remote attacker could gain access to arbitrary files readable by the
    user running the application.
  
Workaround

    Disable the web interface or restrict access to it.
  
');
script_set_attribute(attribute:'solution', value: '
    All MLDonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-p2p/mldonkey-3.0.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0753');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-36.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-36] MLDonkey: Information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MLDonkey: Information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-p2p/mldonkey", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
