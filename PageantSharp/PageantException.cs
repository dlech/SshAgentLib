using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dlech.PageantSharp
{
  /// <summary>
  /// Indicates that another instance of Pageant is already running and a new
  /// instance could not be started
  /// </summary>
	public class PageantRunningException : Exception
	{

	}
}
