using System;

namespace BCrypt.Net
{
    /// <summary>
    /// Exception used to signal errors that occur during use of the hash information methods
    /// </summary>
    public sealed class HashInformationException : Exception
    {
        public HashInformationException()
        {
        }

        public HashInformationException(string message) : base(message)
        {
        }

        public HashInformationException(string message, Exception innerException) : base(message, innerException)
        {
        }

    }
}