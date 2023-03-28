defmodule BinaryProxyServer do
  require Logger

  @doc """
  Starts accepting connections on the given `port`.
  """
  def accept(port) do
    {:ok, socket} = :gen_tcp.listen(port,
                      [:binary, packet: 0, active: false, reuseaddr: true])
    Logger.info "Accepting connections on port #{port}"
    loop_acceptor(socket)
  end

  defp loop_acceptor(socket) do
    {:ok, client} = :gen_tcp.accept(socket)
    {:ok, pid} = Task.Supervisor.start_child(BinaryProxyServer.TaskSupervisor, fn -> start_connection(client) end)
    :ok = :gen_tcp.controlling_process(client, pid)
    loop_acceptor(socket)
  end

  defp start_connection(socket) do
    :timer.sleep(100)
    nonce = :crypto.strong_rand_bytes(16)
    serve(socket,0,"", nonce)
  end

  defp serve(socket, state, pub, nonce) do
    oldnonce = nonce
    nonce = :crypto.strong_rand_bytes(16)

    msg = with {:ok, data} <- read_line(socket),
                do: BinaryProxyServer.Command.parsePackage(data, state, pub, nonce, oldnonce)

    case msg do
      {:ok, _cmessage, cstate, cpub} ->
        write_line(socket, msg, nonce)
        serve(socket, cstate, cpub, nonce)
      {:error, :invalid_data} ->
        case state do
          0 -> exit(:shutdown)
          1 -> exit(:shutdown)
          _ ->
            write_line(socket, msg, nonce)
            serve(socket, state, pub, nonce)
        end
      _ ->
        write_line(socket, msg, nonce)
        serve(socket, state, pub, nonce)
    end 
  end
  
  defp read_line(socket) do
    :gen_tcp.recv(socket, 0)
  end
  
  defp write_line(socket, {:ok, text, _state, _pub}, _nonce) do
    :gen_tcp.send(socket, text)
  end

  defp write_line(socket, {:error, :invalid_data}, nonce) do
    :gen_tcp.send(socket, << 0x02, 0x00 >> <> nonce)
  end
  
  defp write_line(_socket, {:error, _error}, _nonce) do
    exit(:shutdown)
  end
end
