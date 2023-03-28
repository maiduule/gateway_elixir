defmodule BinaryProxyTest do
  use ExUnit.Case
  doctest BinaryProxy

  test "greets the world" do
    assert BinaryProxy.hello() == :world
  end
end
