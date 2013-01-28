using System;
using dlech.SshAgentLib;

namespace SshAgentLib.GTK
{
  [Gtk.TreeNode (ListOnly=true)]
  public class KeyNode : Gtk.TreeNode 
  {
    private ISshKey mKey;

    [Gtk.TreeNodeValue (Column=0)]
    public bool Confirm
    {
      get
      {
        return mKey.HasConstraint(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      }
    }

    [Gtk.TreeNodeValue (Column=1)]
    public bool Lifetime
    {
      get
      {
        return mKey.HasConstraint(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      }
    }

    [Gtk.TreeNodeValue (Column=2)]
    public string Type
    {
      get
      {
        return mKey.Algorithm.GetIdentifierString();
      }
    }

    [Gtk.TreeNodeValue (Column=3)]
    public int Size
    {
      get
      {
        return mKey.Size;
      }
    }

    [Gtk.TreeNodeValue (Column=4)]
    public string Fingerprint
    {
      get
      {
        return mKey.GetMD5Fingerprint().ToHexString();
      }
    }

    [Gtk.TreeNodeValue (Column=5)]
    public string Comment
    {
      get
      {
        return mKey.Comment;
      }
    }
    
    public KeyNode (ISshKey aKey)
    {
      mKey = aKey;
    }

    public ISshKey GetKey()
    {
      return mKey;
    }

  }
}

