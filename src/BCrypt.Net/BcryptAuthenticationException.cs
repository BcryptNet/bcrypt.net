using System;

namespace BCrypt.Net
{
    /// <summary>Exception for signalling hash validation errors. </summary>
    public class BcryptAuthenticationException : Exception
    {
        /// <summary>Default constructor. </summary>
        public BcryptAuthenticationException()
        {
        }

        /// <summary>Initializes a new instance of <see cref="BcryptAuthenticationException" />.</summary>
        /// <param name="message">The message.</param>
        public BcryptAuthenticationException(string message)
            : base(message)
        {
        }

        /// <summary>Initializes a new instance of <see cref="BcryptAuthenticationException" />.</summary>
        /// <param name="message">       The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public BcryptAuthenticationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}