# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-03.xml
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
 script_id(26043);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200709-03");
 script_cve_id("CVE-2007-4337");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-03
(Streamripper: Buffer overflow)


    Chris Rohlf discovered several boundary errors in the
    httplib_parse_sc_header() function when processing HTTP headers.
  
Impact

    A remote attacker could entice a user to connect to a malicious
    streaming server, resulting in the execution of arbitrary code with the
    privileges of the user running Streamripper.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Streamripper users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/streamripper-1.62.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4337');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-03] Streamripper: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Streamripper: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/streamripper", unaffected: make_list("ge 1.62.2"), vulnerable: make_list("lt 1.62.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
