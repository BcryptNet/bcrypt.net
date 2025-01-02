using System;
using System.Runtime.Serialization;

namespace BCryptNet
{
    #if NETFRAMEWORK
    /// <summary>Exception for signalling hash validation errors. </summary>
    [Serializable]
    public sealed class BcryptAuthenticationException : Exception
    {
        /// <summary>
        ///     Default Constructor
        /// </summary>
        protected BcryptAuthenticationException()
        {
        }

        /// <inheritdoc />
        protected BcryptAuthenticationException(SerializationInfo info, StreamingContext streamingContext) : base(info, streamingContext)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="BcryptAuthenticationException" />.
        /// </summary>
        /// <param name="message"></param>
        public BcryptAuthenticationException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="BcryptAuthenticationException" />.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public BcryptAuthenticationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
#else
    /// <summary>Exception for signalling hash validation errors. </summary>
    public sealed class BcryptAuthenticationException : Exception
    {
        /// <summary>
        ///     Default Constructor
        /// </summary>
        public BcryptAuthenticationException()
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="BcryptAuthenticationException" />.
        /// </summary>
        /// <param name="message"></param>
        public BcryptAuthenticationException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="BcryptAuthenticationException" />.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public BcryptAuthenticationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
#endif
}
