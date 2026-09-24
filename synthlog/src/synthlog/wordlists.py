"""Small built-in word lists so entity patterns like "{first}.{last}" need no extra dependency."""

FIRST = (
    "adam alex alice amir ana andre anna ari ben beth carla carlos chen chris dana daniel david "
    "dmitri eli ella emma eric eva fatima felix gal george hana ivan jack jana james jin john jonas "
    "julia karen kate kim lars lea leo lina liam lucas maya maria mark max mia michael mika nadia "
    "noa noah nina omar oren paul peter priya rachel rami rita ron rosa sam sara sofia tal tom "
    "uri vera victor yael yuki zoe"
).split()

LAST = (
    "adams baker brown carter chen cohen cruz davis diaz evans fischer garcia gray green hall harris "
    "hill ito jensen jones kaplan kim klein lee levi lopez martin meyer miller moore murphy nguyen "
    "novak park patel perez peretz reed rossi sato schmidt shah silva singh smith tanaka taylor "
    "turner walker wang white wilson wong young zhang"
).split()

WORDS = (
    "alpha amber anchor apex arrow atlas aurora beacon birch blaze bolt canyon cedar cipher cobalt "
    "comet coral crest delta drift ember falcon fern flint forge frost garnet glacier harbor hazel "
    "helix horizon indigo iris jade juniper kestrel lumen maple meadow mercury mesa nova oak onyx "
    "orbit pine pixel prism quartz raven ridge river sage sierra slate solar spruce summit tango "
    "terra tidal topaz vector willow zenith"
).split()

DOMAINS = ("example.com", "example.org", "example.net")
