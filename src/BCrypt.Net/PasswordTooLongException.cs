// ReSharper disable once RedundantUsingDirective
using System;
using System.Runtime.Serialization;

namespace BCryptNet
{
    #if PRE_CORE
    /// <summary>
    ///     Exception used to signal errors that occur during salt-parsing
    /// </summary>
    [Serializable]
    public sealed class PasswordTooLongException : Exception
    {
        /// <summary>
        ///     Default Constructor
        /// </summary>
        private PasswordTooLongException()
        {
        }

        /// <inheritdoc />
        private PasswordTooLongException(SerializationInfo info, StreamingContext streamingContext) : base(info, streamingContext)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="PasswordTooLongException" />.
        /// </summary>
        /// <param name="message"></param>
        public PasswordTooLongException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="PasswordTooLongException" />.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public PasswordTooLongException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
#else
    /// <summary>
    ///     Exception used to signal errors that occur during salt-parsing
    /// </summary>
    public sealed class PasswordTooLongException : Exception
    {
        /// <summary>
        ///     Default Constructor
        /// </summary>
        public PasswordTooLongException()
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="PasswordTooLongException" />.
        /// </summary>
        /// <param name="message"></param>
        public PasswordTooLongException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="PasswordTooLongException" />.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public PasswordTooLongException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
#endif
}
