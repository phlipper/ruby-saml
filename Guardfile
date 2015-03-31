# only include directories you want to watch
directories %w[lib test]

# clear the screen before every task
clearing :on

guard :minitest do
  watch(%r{^test/(.*)\/?(.*)_test\.rb$})
  watch(%r{^test/test_helper\.rb$}) { "test" }
  watch(%r{^lib/(?:onelogin/ruby\-saml/)?([^/]+)\.rb$}) do |match|
    "test/#{match[1]}_test.rb"
  end
end
