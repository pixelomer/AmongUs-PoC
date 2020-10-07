using System;
using Hazel.Udp.FewerThreads;
using Hazel;
using System.Net;
using System.Threading;
using System.Collections.Generic;

namespace HazelTestServer
{
    class Program
    {

        static void Main(string[] args)
        {
            //
            // There isn't really a bug in the MessageReader.GetSized() function.
            // However, when you are able to read data out of bounds, it causes
            // problems. MessageReader.GetSized() returns a reader from a reader
            // pool, and it does not empty the buffer of the reader before returning
            // it. This means that there will still be left-overs from previous
            // packets. This is what the client leaks.
            //

            //
            // To simulate a realistic server, this code creates and recycles 10
            // message readers. This causes the reader pool to fill up with readers
            // that have left-over data in their buffers. In a real server, these
            // readers would contain data from old packets.
            //
            {
                const int readerCount = 10;
                List<MessageReader> readers = new List<MessageReader>(readerCount);
                Random generator = new Random();
                for (int i = 0; i < readerCount; i++)
                {
                    MessageReader reader = MessageReader.GetSized(0x10000);
                    for (int j = 0; j < 0x10000; j++)
                    {
                        reader.Buffer[j] = Convert.ToByte(generator.Next(0xFF));
                    }
                    readers.Add(reader);
                }
                foreach (MessageReader reader in readers)
                {
                    reader.Recycle();
                }
            }

            using (var udpServer = new ThreadLimitedUdpConnectionListener(8, new IPEndPoint(IPAddress.Loopback, 22023), null, IPMode.IPv4))
            {
                udpServer.NewConnection += HandleNewConnection;
                udpServer.Start();
                Console.WriteLine("Listening to new connections...");
                while (true)
                {
                    Thread.Sleep(60000);
                }
            }
        }

        static void HandleNewConnection(NewConnectionEventArgs args)
        {
            Console.WriteLine("New connection");
            args.Connection.DataReceived += HandleNewMessage;
        }

        static unsafe void HandleNewMessage(DataReceivedEventArgs args)
        {
            MessageReader reader = args.Message.ReadMessage();
            try
            {
                Console.WriteLine("New message");

                // Simulate the Among Us server response
                string input = $"Inappropriate name: {reader.ReadString()}";
                MessageWriter writer = MessageWriter.Get(SendOption.None);
                writer.StartMessage(reader.Tag);
                writer.Write(input);
                writer.EndMessage();
                args.Sender.Send(writer);
                writer.Recycle();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                reader.Recycle();
                args.Message.Recycle();
            }
        }
    }
}
