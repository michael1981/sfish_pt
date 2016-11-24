# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-13.xml
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
 script_id(14478);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200404-13");
 script_cve_id("CVE-2004-0180", "CVE-2004-0405");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-13
(CVS Server and Client Vulnerabilities)


    There are two vulnerabilities in CVS; one in the server and one in the
    client. The server vulnerability allows a malicious client to request
    the contents of any RCS file to which the server has permission, even
    those not located under $CVSROOT. The client vulnerability allows a
    malicious server to overwrite files on the client machine anywhere the
    client has permissions.
  
Impact

    Arbitrary files may be read or written on CVS clients and servers by
    anybody with access to the CVS tree.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest stable version of CVS.
  
');
script_set_attribute(attribute:'solution', value: '
    All CVS users should upgrade to the latest stable version.
    # emerge sync
    # emerge -pv ">=dev-util/cvs-1.11.15"
    # emerge ">=dev-util/cvs-1.11.15"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://ccvs.cvshome.org/source/browse/ccvs/NEWS?rev=1.116.2.92&content-type=text/x-cvsweb-markup');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0180');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0405');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-13] CVS Server and Client Vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CVS Server and Client Vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/cvs", unaffected: make_list("ge 1.11.15"), vulnerable: make_list("le 1.11.14")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
