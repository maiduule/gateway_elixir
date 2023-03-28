defmodule BinaryProxy.Bucket do
  use Agent, restart: :temporary

  @doc """
  Starts a new bucket.
  """
  def start_link(_opts) do
    Agent.start_link(fn -> [] end)
  end

  @doc """
  Gets a value from the `bucket` by `key`.
  """
  def get(bucket) do
    value = Agent.get(bucket, fn list -> List.first(list, "EMPTY") end)
    case value do
      "EMPTY" ->
        value
      _ ->
        Agent.update(bucket, fn list -> List.delete_at(list, 0) end)
        value
    end
  end

  @doc """
  Puts the `value` for the given `key` in the `bucket`.
  """
  def put(bucket, value) do
    Agent.update(bucket, fn list -> list ++ [value] end)
  end
end