require "spec_helper"

RSpec.describe Vulscan do
  it "has a version number" do
    expect(Vulscan::VERSION).not_to be nil
  end
end
