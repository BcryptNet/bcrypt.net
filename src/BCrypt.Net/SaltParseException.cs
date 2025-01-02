using System;
using System.Runtime.Serialization;

namespace BCryptNet
{
    #if NETFRAMEWORK
    /// <summary>
    ///     Exception used to signal errors that occur during use salt parsing
    /// </summary>
    [Serializable]
    public sealed class SaltParseException : Exception
    {
        /// <summary>
        ///     Default Constructor
        /// </summary>
        protected SaltParseException()
        {
        }

        /// <inheritdoc />
        protected SaltParseException(SerializationInfo info, StreamingContext streamingContext) : base(info, streamingContext)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="SaltParseException" />.
        /// </summary>
        /// <param name="message"></param>
        public SaltParseException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="SaltParseException" />.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public SaltParseException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
#else
    /// <summary>
    ///     Exception used to signal errors that occur during salt parsing
    /// </summary>
    public sealed class SaltParseException : Exception
    {
        /// <summary>
        ///     Default Constructor
        /// </summary>
        public SaltParseException()
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="SaltParseException" />.
        /// </summary>
        /// <param name="message"></param>
        public SaltParseException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="SaltParseException" />.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public SaltParseException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
#endif
}
