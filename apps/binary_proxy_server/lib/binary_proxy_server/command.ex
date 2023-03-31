defmodule BinaryProxyServer.Command do
    require Logger

    @signed_curve :secp256r1

    def parsePackage(data, state, pub, nonce, oldnonce) do
        <<command::binary-size(1), rest::binary>> = data
        case command do
          <<0x03>> -> parseGetNonce(state, pub, nonce, oldnonce)
          <<0x04>> -> parseInit(data, state, pub, nonce, oldnonce)
          <<0x05>> -> parseGet(data, state, pub, nonce, oldnonce)
          <<0x06>> -> parseSend(data, state, pub, nonce, oldnonce)
          _ -> {:error, :invalid_data}
        end
    end

    def parseGetNonce( state, pub, nonce, oldnonce) do
        case state do
            0 ->
                response = << 0x01, 0x03 >> <> nonce
                {:ok, response, 1, pub}
            1 ->
                {:error, :invalid_state}
            _ ->
                response = << 0x01, 0x03 >> <> nonce
                {:ok, response, state, pub}
        end     
    end

    defp expand_to_64_blocks(message)
       when byte_size(message) / 64 == round(byte_size(message) / 64) do
        message
    end

    defp expand_to_64_blocks(message) do
        message
        |> split_to_64_bytes
        |> Enum.map(fn
        b when byte_size(b) == 64 -> b
        b -> padding(b, 64)
        end)
        |> Enum.reduce(<<>>, fn x, acc -> acc <> x end)
    end

    defp split_to_64_bytes(<<>>), do: []

    defp split_to_64_bytes(data) when byte_size(data) <= 64 do
        [data]
    end

    defp split_to_64_bytes(data) when byte_size(data) > 64 do
        {chunk, rest} = :erlang.split_binary(data, 64)
        [chunk | split_to_64_bytes(rest)]
    end

    defp padding(message, size) do
        message <> :binary.copy(<<0x00>>, size - byte_size(message))
    end

    defp fill_signature(<<vr::binary-size(32), vs::binary-size(32)>>) do
        vr = String.trim_leading(vr, <<0x00>>)
        vs = String.trim_leading(vs, <<0x00>>)
        vr = prepand_zero_if_needed(vr)
        vs = prepand_zero_if_needed(vs)
        b2 = byte_size(vr)
        b3 = byte_size(vs)
        b1 = 4 + b2 + b3
        <<0x30, b1, 0x02, b2>> <> vr <> <<0x02, b3>> <> vs
    end

    defp fill_signature(_) do
    <<>>
    end

    defp prepand_zero_if_needed(<<1::size(1), _::size(7), _::binary>> = bytes) do
    <<0x00>> <> bytes
    end

    defp prepand_zero_if_needed(bytes), do: bytes

    def parseInit(data, state, pub, nonce, oldnonce) do
        case state do
            0 ->
                {:error, :invalid_state}
            1 ->
                if byte_size(data) == 145 do
                    <<command::binary-size(1), inonce::binary-size(16), ipub::binary-size(64), isignature::binary-size(64)>> = data
                    pubforverify = <<0x4>> <> ipub
                    messagetoverify =  command <> inonce <> ipub
                    message = expand_to_64_blocks(messagetoverify)

                    if inonce == oldnonce do
                        signatureverify = :crypto.verify(:ecdsa, :sha256, expand_to_64_blocks(messagetoverify), fill_signature(isignature), [pubforverify, @signed_curve])

                        if signatureverify == true do
                            BinaryProxy.Registry.create(BinaryProxy.Registry, ipub)
                            response = << 0x01, 0x04 >> <> nonce
                            {:ok, response, 2, ipub}
                        else
                            {:error, :invalid_data}
                        end
                    else
                        {:error, :invalid_data}
                    end
                else
                    {:error, :invalid_data}
                end     
            _ ->
                {:error, :invalid_data}
        end     
    end

  def parseGet(data, 0, pub, nonce, oldnonce), do: {:error, :invalid_state}
  def parseGet(data, 1, pub, nonce, oldnonce), do: {:error, :invalid_state}

  def parseGet(data, state, pub, nonce, oldnonce) do
    with {:ok, pid} <- BinaryProxy.Registry.lookup(BinaryProxy.Registry, pub),
         {:ok, response} <- check_empty_value(nonce, pid) do
      {:ok, response, state, pub}
    else
      _ ->
        {:error, :invalid_data}
    end
  end

  defp check_empty_value(nonce, pid) do
    case BinaryProxy.Bucket.get(pid) do
      "EMPTY" ->
        :error

      value ->
        <<0x01, 0x05>> <> nonce <> value
    end
  end

    def parseSend(data, state, pub, nonce, oldnonce) do
        case state do
            0 ->
                {:error, :invalid_state}
            1 ->
                {:error, :invalid_state}
            _ ->

                #Split command byte and container
                <<command::binary-size(1), istoredata::bitstring >> = data

                #extract header info from container
                << isize::big-signed-integer-size(32), inonce::binary-size(16), 
                isenderpub::binary-size(64), ireceiversize::big-signed-integer-size(8),
                isendtopub::binary-size(64), isendtokey::binary-size(16), idata::bitstring>> = istoredata

                if isize < byte_size(data) do
                    if inonce == oldnonce do
                        if isenderpub == pub do
    
                            #split container data and signature
                            <<messagetoverify::binary-size(isize), isignature::bitstring >> = istoredata
    
                            pubforverify = <<0x4>> <> isenderpub
                            signatureverify = :crypto.verify(:ecdsa, :sha256, expand_to_64_blocks(messagetoverify), fill_signature(isignature), [pubforverify, @signed_curve])
    
                            if signatureverify == true do
                                case BinaryProxy.Registry.lookup(BinaryProxy.Registry, isendtopub) do
                                    {:ok, pid} -> 
                                        BinaryProxy.Bucket.put(pid, istoredata)
                                        response = << 0x01, 0x06 >> <> nonce
                                        {:ok, response, state, pub}
                                    :error -> 
                                        {:error, :invalid_data}
                                end
                            else
                                {:error, :invalid_data}
                            end
                        else
                            {:error, :invalid_data}
                        end
                    else
                        {:error, :invalid_data}
                    end
                else
                    {:error, :invalid_data}
                end
        end    
    end
end
