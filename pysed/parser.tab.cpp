//-----------------------------------------------------------------------------
// Do NOT modify or remove this copyright
//
// Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ****************************************************************************
//
// \file parser.tab.cpp
// \brief Implements the Tcg::parser class.
//
//-----------------------------------------------------------------------------
#line 64 "parser.ypp" // lalr1.cc:397

    #include "TcgScanner.h"
    #include "Tcg.h"

    static Tcg::Parser::symbol_type yylex(Tcg::Scanner &scanner) {
	    return scanner.get_next_token();
    }

	Tcg::Uid UidFromToken(boost::python::object & val)
	{
		std::string value = extract<std::string>(val);
		const uint8_t * ptr = (const uint8_t *) value.c_str();
		size_t len = value.length();
		Tcg::Uid uid = 0;
		for (unsigned i = 0; i < len; i++)
			uid = (uid << 8) + ptr[i];
		return uid;
	}


#line 55 "parser.tab.cpp" // lalr1.cc:397

// First part of user declarations.

#line 60 "parser.tab.cpp" // lalr1.cc:404

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

#include "parser.tab.hpp"

// User implementation prologue.

#line 74 "parser.tab.cpp" // lalr1.cc:412


#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> // FIXME: INFRINGES ON USER NAME SPACE.
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif



// Suppress unused-variable warnings by "using" E.
#define YYUSE(E) ((void) (E))

// Enable debugging if requested.
#if YYDEBUG

// A pseudo ostream that takes yydebug_ into account.
# define YYCDEBUG if (yydebug_) (*yycdebug_)

# define YY_SYMBOL_PRINT(Title, Symbol)         \
  do {                                          \
    if (yydebug_)                               \
    {                                           \
      *yycdebug_ << Title << ' ';               \
      yy_print_ (*yycdebug_, Symbol);           \
      *yycdebug_ << std::endl;                  \
    }                                           \
  } while (false)

# define YY_REDUCE_PRINT(Rule)          \
  do {                                  \
    if (yydebug_)                       \
      yy_reduce_print_ (Rule);          \
  } while (false)

# define YY_STACK_PRINT()               \
  do {                                  \
    if (yydebug_)                       \
      yystack_print_ ();                \
  } while (false)

#else // !YYDEBUG

# define YYCDEBUG if (false) std::cerr
# define YY_SYMBOL_PRINT(Title, Symbol)  YYUSE(Symbol)
# define YY_REDUCE_PRINT(Rule)           static_cast<void>(0)
# define YY_STACK_PRINT()                static_cast<void>(0)

#endif // !YYDEBUG

#define yyerrok         (yyerrstatus_ = 0)
#define yyclearin       (yyla.clear ())

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYRECOVERING()  (!!yyerrstatus_)

#line 9 "parser.ypp" // lalr1.cc:479
namespace  Tcg  {
#line 141 "parser.tab.cpp" // lalr1.cc:479

  /* Return YYSTR after stripping away unnecessary quotes and
     backslashes, so that it's suitable for yyerror.  The heuristic is
     that double-quoting is unnecessary unless the string contains an
     apostrophe, a comma, or backslash (other than backslash-backslash).
     YYSTR is taken from yytname.  */
  std::string
   Parser ::yytnamerr_ (const char *yystr)
  {
    if (*yystr == '"')
      {
        std::string yyr = "";
        char const *yyp = yystr;

        for (;;)
          switch (*++yyp)
            {
            case '\'':
            case ',':
              goto do_not_strip_quotes;

            case '\\':
              if (*++yyp != '\\')
                goto do_not_strip_quotes;
              // Fall through.
            default:
              yyr += *yyp;
              break;

            case '"':
              return yyr;
            }
      do_not_strip_quotes: ;
      }

    return yystr;
  }


  /// Build a parser object.
   Parser :: Parser  (Scanner &scanner_yyarg, Results &results_yyarg, Session * session_yyarg)
    :
#if YYDEBUG
      yydebug_ (false),
      yycdebug_ (&std::cerr),
#endif
      scanner (scanner_yyarg),
      results (results_yyarg),
      session (session_yyarg)
  {}

   Parser ::~ Parser  ()
  {}


  /*---------------.
  | Symbol types.  |
  `---------------*/



  // by_state.
  inline
   Parser ::by_state::by_state ()
    : state (empty_state)
  {}

  inline
   Parser ::by_state::by_state (const by_state& other)
    : state (other.state)
  {}

  inline
  void
   Parser ::by_state::clear ()
  {
    state = empty_state;
  }

  inline
  void
   Parser ::by_state::move (by_state& that)
  {
    state = that.state;
    that.clear ();
  }

  inline
   Parser ::by_state::by_state (state_type s)
    : state (s)
  {}

  inline
   Parser ::symbol_number_type
   Parser ::by_state::type_get () const
  {
    if (state == empty_state)
      return empty_symbol;
    else
      return yystos_[state];
  }

  inline
   Parser ::stack_symbol_type::stack_symbol_type ()
  {}


  inline
   Parser ::stack_symbol_type::stack_symbol_type (state_type s, symbol_type& that)
    : super_type (s)
  {
      switch (that.type_get ())
    {
      case 23: // values
        value.move< list > (that.value);
        break;

      case 3: // AtomInt
        value.move< long_ > (that.value);
        break;

      case 22: // value
      case 25: // atom
      case 26: // list
        value.move< object > (that.value);
        break;

      case 4: // AtomString
      case 5: // AtomStringC
      case 24: // atom_string
        value.move< str > (that.value);
        break;

      default:
        break;
    }

    // that is emptied.
    that.type = empty_symbol;
  }

  inline
   Parser ::stack_symbol_type&
   Parser ::stack_symbol_type::operator= (const stack_symbol_type& that)
  {
    state = that.state;
      switch (that.type_get ())
    {
      case 23: // values
        value.copy< list > (that.value);
        break;

      case 3: // AtomInt
        value.copy< long_ > (that.value);
        break;

      case 22: // value
      case 25: // atom
      case 26: // list
        value.copy< object > (that.value);
        break;

      case 4: // AtomString
      case 5: // AtomStringC
      case 24: // atom_string
        value.copy< str > (that.value);
        break;

      default:
        break;
    }

    return *this;
  }


  template <typename Base>
  inline
  void
   Parser ::yy_destroy_ (const char* yymsg, basic_symbol<Base>& yysym) const
  {
    if (yymsg)
      YY_SYMBOL_PRINT (yymsg, yysym);
  }

#if YYDEBUG
  template <typename Base>
  void
   Parser ::yy_print_ (std::ostream& yyo,
                                     const basic_symbol<Base>& yysym) const
  {
    std::ostream& yyoutput = yyo;
    YYUSE (yyoutput);
    symbol_number_type yytype = yysym.type_get ();
    // Avoid a (spurious) G++ 4.8 warning about "array subscript is
    // below array bounds".
    if (yysym.empty ())
      std::abort ();
    yyo << (yytype < yyntokens_ ? "token" : "nterm")
        << ' ' << yytname_[yytype] << " (";
    YYUSE (yytype);
    yyo << ')';
  }
#endif

  inline
  void
   Parser ::yypush_ (const char* m, state_type s, symbol_type& sym)
  {
    stack_symbol_type t (s, sym);
    yypush_ (m, t);
  }

  inline
  void
   Parser ::yypush_ (const char* m, stack_symbol_type& s)
  {
    if (m)
      YY_SYMBOL_PRINT (m, s);
    yystack_.push (s);
  }

  inline
  void
   Parser ::yypop_ (unsigned int n)
  {
    yystack_.pop (n);
  }

#if YYDEBUG
  std::ostream&
   Parser ::debug_stream () const
  {
    return *yycdebug_;
  }

  void
   Parser ::set_debug_stream (std::ostream& o)
  {
    yycdebug_ = &o;
  }


   Parser ::debug_level_type
   Parser ::debug_level () const
  {
    return yydebug_;
  }

  void
   Parser ::set_debug_level (debug_level_type l)
  {
    yydebug_ = l;
  }
#endif // YYDEBUG

  inline  Parser ::state_type
   Parser ::yy_lr_goto_state_ (state_type yystate, int yysym)
  {
    int yyr = yypgoto_[yysym - yyntokens_] + yystate;
    if (0 <= yyr && yyr <= yylast_ && yycheck_[yyr] == yystate)
      return yytable_[yyr];
    else
      return yydefgoto_[yysym - yyntokens_];
  }

  inline bool
   Parser ::yy_pact_value_is_default_ (int yyvalue)
  {
    return yyvalue == yypact_ninf_;
  }

  inline bool
   Parser ::yy_table_value_is_error_ (int yyvalue)
  {
    return yyvalue == yytable_ninf_;
  }

  int
   Parser ::parse ()
  {
    // State.
    int yyn;
    /// Length of the RHS of the rule being reduced.
    int yylen = 0;

    // Error handling.
    int yynerrs_ = 0;
    int yyerrstatus_ = 0;

    /// The lookahead symbol.
    symbol_type yyla;

    /// The return value of parse ().
    int yyresult;

    // FIXME: This shoud be completely indented.  It is not yet to
    // avoid gratuitous conflicts when merging into the master branch.
    try
      {
    YYCDEBUG << "Starting parse" << std::endl;


    /* Initialize the stack.  The initial state will be set in
       yynewstate, since the latter expects the semantical and the
       location values to have been already stored, initialize these
       stacks with a primary value.  */
    yystack_.clear ();
    yypush_ (YY_NULLPTR, 0, yyla);

    // A new symbol was pushed on the stack.
  yynewstate:
    YYCDEBUG << "Entering state " << yystack_[0].state << std::endl;

    // Accept?
    if (yystack_[0].state == yyfinal_)
      goto yyacceptlab;

    goto yybackup;

    // Backup.
  yybackup:

    // Try to take a decision without lookahead.
    yyn = yypact_[yystack_[0].state];
    if (yy_pact_value_is_default_ (yyn))
      goto yydefault;

    // Read a lookahead token.
    if (yyla.empty ())
      {
        YYCDEBUG << "Reading a token: ";
        try
          {
            symbol_type yylookahead (yylex (scanner));
            yyla.move (yylookahead);
          }
        catch (const syntax_error& yyexc)
          {
            error (yyexc);
            goto yyerrlab1;
          }
      }
    YY_SYMBOL_PRINT ("Next token is", yyla);

    /* If the proper action on seeing token YYLA.TYPE is to reduce or
       to detect an error, take that action.  */
    yyn += yyla.type_get ();
    if (yyn < 0 || yylast_ < yyn || yycheck_[yyn] != yyla.type_get ())
      goto yydefault;

    // Reduce or error.
    yyn = yytable_[yyn];
    if (yyn <= 0)
      {
        if (yy_table_value_is_error_ (yyn))
          goto yyerrlab;
        yyn = -yyn;
        goto yyreduce;
      }

    // Count tokens shifted since error; after three, turn off error status.
    if (yyerrstatus_)
      --yyerrstatus_;

    // Shift the lookahead token.
    yypush_ ("Shifting", yyn, yyla);
    goto yynewstate;

  /*-----------------------------------------------------------.
  | yydefault -- do the default action for the current state.  |
  `-----------------------------------------------------------*/
  yydefault:
    yyn = yydefact_[yystack_[0].state];
    if (yyn == 0)
      goto yyerrlab;
    goto yyreduce;

  /*-----------------------------.
  | yyreduce -- Do a reduction.  |
  `-----------------------------*/
  yyreduce:
    yylen = yyr2_[yyn];
    {
      stack_symbol_type yylhs;
      yylhs.state = yy_lr_goto_state_(yystack_[yylen].state, yyr1_[yyn]);
      /* Variants are always initialized to an empty instance of the
         correct type. The default '$$ = $1' action is NOT applied
         when using variants.  */
        switch (yyr1_[yyn])
    {
      case 23: // values
        yylhs.value.build< list > ();
        break;

      case 3: // AtomInt
        yylhs.value.build< long_ > ();
        break;

      case 22: // value
      case 25: // atom
      case 26: // list
        yylhs.value.build< object > ();
        break;

      case 4: // AtomString
      case 5: // AtomStringC
      case 24: // atom_string
        yylhs.value.build< str > ();
        break;

      default:
        break;
    }



      // Perform the reduction.
      YY_REDUCE_PRINT (yyn);
      try
        {
          switch (yyn)
            {
  case 2:
#line 105 "parser.ypp" // lalr1.cc:859
    {YYACCEPT;}
#line 568 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 3:
#line 107 "parser.ypp" // lalr1.cc:859
    { session->endSessionAck(); YYACCEPT; }
#line 574 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 9:
#line 117 "parser.ypp" // lalr1.cc:859
    { results.setReturnedValues(yystack_[0].value.as< object > ());}
#line 580 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 10:
#line 120 "parser.ypp" // lalr1.cc:859
    {yylhs.value.as< object > ()=yystack_[0].value.as< object > ();}
#line 586 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 11:
#line 122 "parser.ypp" // lalr1.cc:859
    {yylhs.value.as< object > ()=yystack_[0].value.as< object > ();}
#line 592 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 12:
#line 124 "parser.ypp" // lalr1.cc:859
    {yylhs.value.as< object > () = make_tuple(yystack_[2].value.as< str > (), yystack_[1].value.as< object > ());}
#line 598 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 13:
#line 126 "parser.ypp" // lalr1.cc:859
    {yylhs.value.as< object > () = make_tuple(yystack_[2].value.as< long_ > (), yystack_[1].value.as< object > ());}
#line 604 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 14:
#line 129 "parser.ypp" // lalr1.cc:859
    { yylhs.value.as< list > () == list();	}
#line 610 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 15:
#line 131 "parser.ypp" // lalr1.cc:859
    { yylhs.value.as< list > () = yystack_[1].value.as< list > (); yylhs.value.as< list > ().append(yystack_[0].value.as< object > ());}
#line 616 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 16:
#line 134 "parser.ypp" // lalr1.cc:859
    {yylhs.value.as< str > () = yystack_[0].value.as< str > ();}
#line 622 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 17:
#line 136 "parser.ypp" // lalr1.cc:859
    { yystack_[1].value.as< str > () += yystack_[0].value.as< str > ();	yylhs.value.as< str > () = yystack_[1].value.as< str > ();}
#line 628 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 18:
#line 139 "parser.ypp" // lalr1.cc:859
    {yylhs.value.as< object > () = yystack_[0].value.as< long_ > ();}
#line 634 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 19:
#line 141 "parser.ypp" // lalr1.cc:859
    {yylhs.value.as< object > () = yystack_[0].value.as< str > ();}
#line 640 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 20:
#line 143 "parser.ypp" // lalr1.cc:859
    {yylhs.value.as< object > () = object();}
#line 646 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 21:
#line 146 "parser.ypp" // lalr1.cc:859
    {
	results.convertNamedList(yystack_[1].value.as< list > (), yylhs.value.as< object > ());
	}
#line 654 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 22:
#line 151 "parser.ypp" // lalr1.cc:859
    {
	Tcg::Uid		objectId = UidFromToken(yystack_[2].value.as< str > ());
	Tcg::Uid		methodId = UidFromToken(yystack_[1].value.as< str > ());
	list	   parms = extract<list>(yystack_[0].value.as< object > ());
	//std::string dbg = extract<std::string>(str($4));
	//YYCDEBUG << "XXXX call: " << std::hex << objectId << ':' << methodId << std::dec << ' ' << dbg << std::endl;
	session->callBack(objectId, methodId, parms);
	}
#line 667 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 23:
#line 161 "parser.ypp" // lalr1.cc:859
    { results.setResultCode(yystack_[3].value.as< long_ > ()); }
#line 673 "parser.tab.cpp" // lalr1.cc:859
    break;

  case 25:
#line 165 "parser.ypp" // lalr1.cc:859
    { session->endSessionAck(); }
#line 679 "parser.tab.cpp" // lalr1.cc:859
    break;


#line 683 "parser.tab.cpp" // lalr1.cc:859
            default:
              break;
            }
        }
      catch (const syntax_error& yyexc)
        {
          error (yyexc);
          YYERROR;
        }
      YY_SYMBOL_PRINT ("-> $$ =", yylhs);
      yypop_ (yylen);
      yylen = 0;
      YY_STACK_PRINT ();

      // Shift the result of the reduction.
      yypush_ (YY_NULLPTR, yylhs);
    }
    goto yynewstate;

  /*--------------------------------------.
  | yyerrlab -- here on detecting error.  |
  `--------------------------------------*/
  yyerrlab:
    // If not already recovering from an error, report this error.
    if (!yyerrstatus_)
      {
        ++yynerrs_;
        error (yysyntax_error_ (yystack_[0].state, yyla));
      }


    if (yyerrstatus_ == 3)
      {
        /* If just tried and failed to reuse lookahead token after an
           error, discard it.  */

        // Return failure if at end of input.
        if (yyla.type_get () == yyeof_)
          YYABORT;
        else if (!yyla.empty ())
          {
            yy_destroy_ ("Error: discarding", yyla);
            yyla.clear ();
          }
      }

    // Else will try to reuse lookahead token after shifting the error token.
    goto yyerrlab1;


  /*---------------------------------------------------.
  | yyerrorlab -- error raised explicitly by YYERROR.  |
  `---------------------------------------------------*/
  yyerrorlab:

    /* Pacify compilers like GCC when the user code never invokes
       YYERROR and the label yyerrorlab therefore never appears in user
       code.  */
    if (false)
      goto yyerrorlab;
    /* Do not reclaim the symbols of the rule whose action triggered
       this YYERROR.  */
    yypop_ (yylen);
    yylen = 0;
    goto yyerrlab1;

  /*-------------------------------------------------------------.
  | yyerrlab1 -- common code for both syntax error and YYERROR.  |
  `-------------------------------------------------------------*/
  yyerrlab1:
    yyerrstatus_ = 3;   // Each real token shifted decrements this.
    {
      stack_symbol_type error_token;
      for (;;)
        {
          yyn = yypact_[yystack_[0].state];
          if (!yy_pact_value_is_default_ (yyn))
            {
              yyn += yyterror_;
              if (0 <= yyn && yyn <= yylast_ && yycheck_[yyn] == yyterror_)
                {
                  yyn = yytable_[yyn];
                  if (0 < yyn)
                    break;
                }
            }

          // Pop the current state because it cannot handle the error token.
          if (yystack_.size () == 1)
            YYABORT;

          yy_destroy_ ("Error: popping", yystack_[0]);
          yypop_ ();
          YY_STACK_PRINT ();
        }


      // Shift the error token.
      error_token.state = yyn;
      yypush_ ("Shifting", error_token);
    }
    goto yynewstate;

    // Accept.
  yyacceptlab:
    yyresult = 0;
    goto yyreturn;

    // Abort.
  yyabortlab:
    yyresult = 1;
    goto yyreturn;

  yyreturn:
    if (!yyla.empty ())
      yy_destroy_ ("Cleanup: discarding lookahead", yyla);

    /* Do not reclaim the symbols of the rule whose action triggered
       this YYABORT or YYACCEPT.  */
    yypop_ (yylen);
    while (1 < yystack_.size ())
      {
        yy_destroy_ ("Cleanup: popping", yystack_[0]);
        yypop_ ();
      }

    return yyresult;
  }
    catch (...)
      {
        YYCDEBUG << "Exception caught: cleaning lookahead and stack"
                 << std::endl;
        // Do not try to display the values of the reclaimed symbols,
        // as their printer might throw an exception.
        if (!yyla.empty ())
          yy_destroy_ (YY_NULLPTR, yyla);

        while (1 < yystack_.size ())
          {
            yy_destroy_ (YY_NULLPTR, yystack_[0]);
            yypop_ ();
          }
        throw;
      }
  }

  void
   Parser ::error (const syntax_error& yyexc)
  {
    error (yyexc.what());
  }

  // Generate an error message.
  std::string
   Parser ::yysyntax_error_ (state_type yystate, const symbol_type& yyla) const
  {
    // Number of reported tokens (one for the "unexpected", one per
    // "expected").
    size_t yycount = 0;
    // Its maximum.
    enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
    // Arguments of yyformat.
    char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];

    /* There are many possibilities here to consider:
       - If this state is a consistent state with a default action, then
         the only way this function was invoked is if the default action
         is an error action.  In that case, don't check for expected
         tokens because there are none.
       - The only way there can be no lookahead present (in yyla) is
         if this state is a consistent state with a default action.
         Thus, detecting the absence of a lookahead is sufficient to
         determine that there is no unexpected or expected token to
         report.  In that case, just report a simple "syntax error".
       - Don't assume there isn't a lookahead just because this state is
         a consistent state with a default action.  There might have
         been a previous inconsistent state, consistent state with a
         non-default action, or user semantic action that manipulated
         yyla.  (However, yyla is currently not documented for users.)
       - Of course, the expected token list depends on states to have
         correct lookahead information, and it depends on the parser not
         to perform extra reductions after fetching a lookahead from the
         scanner and before detecting a syntax error.  Thus, state
         merging (from LALR or IELR) and default reductions corrupt the
         expected token list.  However, the list is correct for
         canonical LR with one exception: it will still contain any
         token that will not be accepted due to an error action in a
         later state.
    */
    if (!yyla.empty ())
      {
        int yytoken = yyla.type_get ();
        yyarg[yycount++] = yytname_[yytoken];
        int yyn = yypact_[yystate];
        if (!yy_pact_value_is_default_ (yyn))
          {
            /* Start YYX at -YYN if negative to avoid negative indexes in
               YYCHECK.  In other words, skip the first -YYN actions for
               this state because they are default actions.  */
            int yyxbegin = yyn < 0 ? -yyn : 0;
            // Stay within bounds of both yycheck and yytname.
            int yychecklim = yylast_ - yyn + 1;
            int yyxend = yychecklim < yyntokens_ ? yychecklim : yyntokens_;
            for (int yyx = yyxbegin; yyx < yyxend; ++yyx)
              if (yycheck_[yyx + yyn] == yyx && yyx != yyterror_
                  && !yy_table_value_is_error_ (yytable_[yyx + yyn]))
                {
                  if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                    {
                      yycount = 1;
                      break;
                    }
                  else
                    yyarg[yycount++] = yytname_[yyx];
                }
          }
      }

    char const* yyformat = YY_NULLPTR;
    switch (yycount)
      {
#define YYCASE_(N, S)                         \
        case N:                               \
          yyformat = S;                       \
        break
        YYCASE_(0, YY_("syntax error"));
        YYCASE_(1, YY_("syntax error, unexpected %s"));
        YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
        YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
        YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
        YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
      }

    std::string yyres;
    // Argument number.
    size_t yyi = 0;
    for (char const* yyp = yyformat; *yyp; ++yyp)
      if (yyp[0] == '%' && yyp[1] == 's' && yyi < yycount)
        {
          yyres += yytnamerr_ (yyarg[yyi++]);
          ++yyp;
        }
      else
        yyres += *yyp;
    return yyres;
  }


  const signed char  Parser ::yypact_ninf_ = -29;

  const signed char  Parser ::yytable_ninf_ = -25;

  const signed char
   Parser ::yypact_[] =
  {
      11,   -29,    18,   -29,    32,   -29,    14,    23,   -29,   -29,
       4,    31,   -29,   -29,   -29,    20,    33,   -29,   -29,    24,
     -29,    -2,   -29,   -29,   -29,   -29,   -29,    34,   -29,    35,
     -29,   -29,    10,    10,   -29,    38,    28,    36,    39,   -29,
     -29,    37,   -29
  };

  const unsigned char
   Parser ::yydefact_[] =
  {
       7,    14,     0,     3,     0,     5,     7,     0,     9,     8,
       0,     0,     1,    25,     6,     0,     0,    18,    16,     0,
      21,     0,    20,    15,    19,    10,    11,     0,     2,     0,
       4,    17,     0,     0,    22,     0,     0,     0,     0,    13,
      12,     0,    23
  };

  const signed char
   Parser ::yypgoto_[] =
  {
     -29,   -29,    40,   -29,   -29,   -28,   -29,    12,   -29,     0,
     -29,   -29,   -29
  };

  const signed char
   Parser ::yydefgoto_[] =
  {
      -1,     4,     5,     6,     7,    23,    10,    24,    25,    26,
       9,    30,    15
  };

  const signed char
   Parser ::yytable_[] =
  {
       8,    32,    18,    19,    36,    37,     8,    17,    18,    19,
       1,    20,    21,    17,    18,    19,     1,     1,    21,    22,
       1,     2,    11,     3,     2,    22,    13,    34,    18,    19,
     -24,    31,    12,    33,    16,    27,    28,    39,    35,    29,
       1,    38,    41,     0,    42,    40,    14
  };

  const signed char
   Parser ::yycheck_[] =
  {
       0,     3,     4,     5,    32,    33,     6,     3,     4,     5,
       6,     7,     8,     3,     4,     5,     6,     6,     8,    15,
       6,    10,     4,    12,    10,    15,    12,    27,     4,     5,
      16,    19,     0,    21,    11,     4,    16,     9,     3,     6,
       6,     3,     3,    -1,     7,     9,     6
  };

  const unsigned char
   Parser ::yystos_[] =
  {
       0,     6,    10,    12,    18,    19,    20,    21,    26,    27,
      23,     4,     0,    12,    19,    29,    11,     3,     4,     5,
       7,     8,    15,    22,    24,    25,    26,     4,    16,     6,
      28,    24,     3,    24,    26,     3,    22,    22,     3,     9,
       9,     3,     7
  };

  const unsigned char
   Parser ::yyr1_[] =
  {
       0,    17,    18,    18,    19,    20,    20,    21,    21,    21,
      22,    22,    22,    22,    23,    23,    24,    24,    25,    25,
      25,    26,    27,    28,    29,    29
  };

  const unsigned char
   Parser ::yyr2_[] =
  {
       0,     2,     3,     1,     3,     1,     2,     0,     1,     1,
       1,     1,     4,     4,     0,     2,     1,     2,     1,     1,
       1,     3,     4,     5,     0,     1
  };



  // YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
  // First, the terminals, then, starting at \a yyntokens_, nonterminals.
  const char*
  const  Parser ::yytname_[] =
  {
  "$end", "error", "$undefined", "AtomInt", "AtomString", "AtomStringC",
  "StartList", "EndList", "StartName", "EndName", "Call", "EndData",
  "EndSession", "StartTransaction", "EndTransaction", "EmptyAtom", "END",
  "$accept", "start", "completion", "completions", "call_or_list", "value",
  "values", "atom_string", "atom", "list", "call", "results",
  "opt_end_session", YY_NULLPTR
  };

#if YYDEBUG
  const unsigned char
   Parser ::yyrline_[] =
  {
       0,   104,   104,   106,   109,   111,   112,   114,   115,   116,
     119,   121,   123,   125,   129,   130,   133,   135,   138,   140,
     142,   145,   150,   160,   163,   164
  };

  // Print the state stack on the debug stream.
  void
   Parser ::yystack_print_ ()
  {
    *yycdebug_ << "Stack now";
    for (stack_type::const_iterator
           i = yystack_.begin (),
           i_end = yystack_.end ();
         i != i_end; ++i)
      *yycdebug_ << ' ' << i->state;
    *yycdebug_ << std::endl;
  }

  // Report on the debug stream that the rule \a yyrule is going to be reduced.
  void
   Parser ::yy_reduce_print_ (int yyrule)
  {
    unsigned int yylno = yyrline_[yyrule];
    int yynrhs = yyr2_[yyrule];
    // Print the symbols being reduced, and their result.
    *yycdebug_ << "Reducing stack by rule " << yyrule - 1
               << " (line " << yylno << "):" << std::endl;
    // The symbols being reduced.
    for (int yyi = 0; yyi < yynrhs; yyi++)
      YY_SYMBOL_PRINT ("   $" << yyi + 1 << " =",
                       yystack_[(yynrhs) - (yyi + 1)]);
  }
#endif // YYDEBUG


#line 9 "parser.ypp" // lalr1.cc:1167
} //  Tcg
#line 1073 "parser.tab.cpp" // lalr1.cc:1167
#line 166 "parser.ypp" // lalr1.cc:1168


void Tcg::Parser::error(const std::string& error)
{
	session->getLogger().debug("TcgParser error - %s at %x:\n%s",
		error.c_str(), scanner.getPos(),
		scanner.getBuffer().c_str());
	throw Tcg::ParserAbort(Tcg::UNEXPECTED_RESULTS);
}
