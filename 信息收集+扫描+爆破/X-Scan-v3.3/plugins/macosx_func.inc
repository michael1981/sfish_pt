#TRUSTED 7775ad8cce8527ec780e46ff1dab01907a6e4902e14d2e2808f9f1441609488d5093448eb0c2acaaf6683e1c9e25a457759cd41cc70051b3d956b84d142929cc371fa8a6c5d1a857e1da50d3e7b56d52db3d5bd18a561efa064e6bc2c2d1215f3b31ad27252acf8138528d964ab8d390e66b623b0f866d87c045dcb89aed08a7fde3e8596e287658a3d25d0bd9eb3b2852760254481e11b4a0d0844d92adc6798f6f2a924b37b0208d31a8dfded07774148d1027554b126c995b67a05d0f0a2877a34f1ee84d382d456832c67eaafba44715a81b07569f405630a89c933e3387b05c7983c889dacc3687dee222e7a4a3dda85882f1a5a5d42d82c3e360243200f31740edd89a035a4d8c7729c985300a579726b89a4913ee1eb86206a059ba6daa760abf3561d4584e982d5220337f50ee650cc8cf8b876285696077b8cf9d82ae9763d6aa50a959851f1ea2198c5da6838f747ab8eb41235b5fa17fbefbbc5f41512fdbb00410fde341b7112d89b554a0ed1624504fe9e3fdaf5c5109c25b40701e25cfa04194ee7bc8e1e2244c0f8e61b0d3f67afeeea570475a0ed63ab4e0cebdf984a1248722966a2cd577b8d488be307392cee41e29fbfd28380ee3aebcb27a2876db9b66d6f569d07f539970b36d0252a29748564fa6846f631d3bb28e402afdae0ed284a305027f488df4a39f34698c9deaeccc3ed6e72e0d4b2ab177
# 
# (C) 2006 Tenable Network Security
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
#


function _GetBundleVersionCmd(file, path, label, rsrc)
{
  local_var ret, suffix;
  local_var cmd;

  if ( rsrc )
  {
    suffix = "/rsrc";
    cmd = "strings";
  }
  else 	
  {
    suffix = "/Contents/version.plist";
    cmd    = "cat";
 }
 

 file = str_replace(find:' ', replace:'\\ ', string:file);

 if ( !isnull(path) )
   {
   path = str_replace(find:' ', replace:'\\ ', string:path);
   ret = "cd " + path + " 2>/dev/null && "; 
   }
 else
   ret = "";


 ret += cmd + " " + file + suffix + "|grep -A 1 " + label + " " + '| tail -n 1 | sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
 return ret;
}


function GetBundleVersionCmd(file, path, long)
{
 if ( long ) 
  return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleVersion", rsrc:FALSE);
 else
  return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleShortVersion", rsrc:FALSE);
}

function GetCarbonVersionCmd(file, path)
{
 return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleVersion", rsrc:TRUE);
}
