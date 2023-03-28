defmodule BinaryProxyServerTest do
  use ExUnit.Case
  doctest BinaryProxyServer

  test "greets the world" do
    assert BinaryProxyServer.hello() == :world
  end
end
