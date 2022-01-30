//
// CallbackNullException.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Indicates that a callback is required but it
    /// has not been assigned a method yet
    /// </summary>
    /// <remarks>
    /// Agent.ConfirmUserPermissionCallback must be assigned a method before
    /// calling AddKey with a key that has a confirm constraint
    /// KeyFormatter.GetPassphraseCallbackMethod must be assigned a method before
    /// attempting to deserialize an encrypted key
    /// </remarks>
    public class CallbackNullException : Exception { }
}
