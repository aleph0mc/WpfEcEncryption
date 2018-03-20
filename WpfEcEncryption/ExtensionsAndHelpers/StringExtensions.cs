using System;
using System.Collections.Generic;
using System.Text;

namespace EllipticCurves.ExtensionsAndHelpers
{
    public static class StringExtensions
    {
        public static string[] SplitInGroup(this string Source, int GroupSize)
        {
            List<string> strLst = new List<string>();

            var len = Source.Length;

            var grpCnt = len / GroupSize; // count groups
            var grpRem = len % GroupSize; // reminder group

            var idx = 0;
            for (int i = 0; i < grpCnt; i++)
            {
                var strGrp = Source.Substring(idx, GroupSize);
                strLst.Add(strGrp);
                idx = (i+1) * GroupSize;

            }

            if (0 != grpRem)
            {
                var strGrp = Source.Substring(idx);
                strLst.Add(strGrp);
            }

            return strLst.ToArray();
        }
    }
}
