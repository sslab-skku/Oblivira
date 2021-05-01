using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using System.Text.Json;

namespace IdentityOverlayNetwork
{
    /// <summary>
    /// QueryInfo class for transferring data
    /// to Oblivira
    /// </summary>
    public class QueryInfo
    {
        public string baseAddress { get; set; }
        public string identifier { get; set; }
    }

    /// <summary>
    /// Connection class for fetching data from
    /// remote servers.
    /// </summary>
    public class Connection : IDisposable
    {
        /// <summary>
        /// Has the object been disposed of?
        /// </summary>
        private bool disposed = false;

        /// <summary>
        /// Instance of the <see cref="IHttpClientFactory" /> for creating
        /// clients <see cref="HttpClient"/>.
        /// </summary>
        private readonly IHttpClientFactory httpClientFactory;

        /// <summary>
        /// Instance of the <see cref="QueryInfo" /> for creating payload
        /// </summary>
        private QueryInfo queryInfo;

        /// <summary>
        /// Initializes an instance of the <see cref="Connection" /> class.
        /// </summary>
        /// <param name="httpClient">The <see cref="HttpClient" /> to initialize the instance.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="httpClient"> is null.</exception>
        public Connection(IHttpClientFactory httpClientFactory)
        {
            this.httpClientFactory = httpClientFactory.IsNull("httpClientFactory");
            this.queryInfo = new QueryInfo();
        }

        /// <summary>
        /// Gets the content from <paramref name="requestUri"/>.
        /// </summary>
        /// <param name="identifier">The identifier string for which to get the content.</param>
        /// <returns>The <see cref="HttpContent"/> returned in the response.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="requestUri"> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="requestUri"> is empty or is whitespace.</exception>
        /// <exception cref="ConnectionException">Thrown when an exception is received makign the request to <paramref name="requestUri">.</exception>
        public async Task<bool> GetAsync(string identifier)
        {
            // Check the argument
            identifier = identifier.IsPopulated("requestUri");

            // Get the http client TODO Update factory logic to return default
            // client and support random client selection etc
            HttpClient httpClient = this.httpClientFactory.CreateClient("default");

            // Configure queryinfo and seralize it
            this.queryInfo.baseAddress = httpClient.BaseAddress.ToString();
            this.queryInfo.identifier = identifier;
            string payload = JsonSerializer.Serialize(this.queryInfo);

            // Create HTTP Request heading to Oblivira
            var httpWebRequest = (HttpWebRequest)WebRequest.Create("http://dockerhost:8081");
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            // Open stream and send POST request to Oblivira
            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                await streamWriter.WriteAsync(payload);
                streamWriter.Flush();
                streamWriter.Close();
            }

            // Get HTTP Response and parse it
            string result = null;
            HttpWebResponse httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            using (StreamReader streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
                Console.Out.WriteLine(result);
            }

            // Check if we have got an OK back, if not
            // throw passing up the reason.
            if (!(httpResponse.StatusCode == HttpStatusCode.OK))
            {
                throw new ConnectionException(httpResponse.StatusCode, result);
            }

            return true;
        }

        /// <summary>
        /// Dispose of the object
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose of the connection object.
        /// </summary>
        /// <param name="disposing">True if the method is called from user code, false if called by finalizer.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (this.disposed || !disposing)
            {
                return;
            }

            // Update the flag to indicate dispose
            // has been called
            this.disposed = true;

            // Dispose of the query info if
            // not already disposed
            if (this.queryInfo != null)
            {
                this.queryInfo = null;
            }
        }
    }
}