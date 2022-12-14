Функция Очистить() Экспорт
	ЭтотОбъект.Ремонты_ПодобныеЗадачи.Очистить();
КонецФункции

Функция Заполнить(Автомобиль) Экспорт
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	ЗадачиЗвонокЛояльности.Контрагент КАК Контрагент,
	|	ЗадачиЗвонокЛояльности.СигнатураПродажи КАК СигнатураПродажи,
	|	ЗадачиЗвонокЛояльности.Телефон КАК Телефон,
	|	ЗадачиЗвонокЛояльности.Телефоны КАК Телефоны,
	|	ЗадачиЗвонокЛояльности.Тип КАК Тип,
	|	ЗадачиЗвонокЛояльности.Исполнитель КАК Исполнитель,
	|	ЗадачиЗвонокЛояльности.Комментарий КАК Комментарий,
	|	ЗадачиЗвонокЛояльности.ДатаЗакрытия КАК ДатаЗакрытия,
	|	ЗадачиЗвонокЛояльности.ДатаПостановки КАК ДатаПостановки,
	|	ЗадачиЗвонокЛояльности.ЗвонокЗакрытия КАК ЗвонокЗакрытия,
	|	ЗадачиЗвонокЛояльности.ДатаАктуальности КАК ДатаАктуальности,
	|	ЗадачиЗвонокЛояльности.ПричинаЗакрытия КАК ПричинаЗакрытия,
	|	ЗадачиЗвонокЛояльности.НапоминаниеПерезвонить КАК НапоминаниеПерезвонить,
	|	ВЫБОР
	|		КОГДА ЗадачиЗвонокЛояльности.ДатаЗакрытия = ДАТАВРЕМЯ(1, 1, 1)
	|			ТОГДА ЛОЖЬ
	|		ИНАЧЕ ИСТИНА
	|	КОНЕЦ КАК Выполнена,
	|	ЕСТЬNULL(Продажи.Дата, ДАТАВРЕМЯ(1, 1, 1)) КАК ДатаДок,
	|	ЕСТЬNULL(Продажи.Номер, """") КАК НомерДок,
	|	ЕСТЬNULL(Продажи.ДопДата, ДАТАВРЕМЯ(1, 1, 1)) КАК ДатаЗакрытияЗаказНаряда,
	|	ЕСТЬNULL(Продажи.Объект, """") КАК Товар,
	|	ЕСТЬNULL(Продажи.ХарактеристикаОбъекта, """") КАК ХарактеристикаТовара,
	|	ЕСТЬNULL(Продажи.Сотрудник, """") КАК Сотрудник,
	|	ЕСТЬNULL(Продажи.Точка, """") КАК ТочкаПродажи,
	|	ЕСТЬNULL(Продажи.КонтактноеЛицо, """") КАК КонтактноеЛицо,
	|	НеПерезваниватьСрезПоследних.Категория КАК Категория,
	|	НеПерезваниватьСрезПоследних.Индикатор КАК Индикатор,
	|	ЗадачиЗвонокЛояльности.ДатаПервогоПерезвона КАК ДатаПервогоПерезвона
	|ИЗ
	|	РегистрСведений.ЗадачиЗвонокЛояльности КАК ЗадачиЗвонокЛояльности
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.Продажи КАК Продажи
	|		ПО ЗадачиЗвонокЛояльности.СигнатураПродажи = Продажи.Сигнатура
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.НеПерезванивать.СрезПоследних КАК НеПерезваниватьСрезПоследних
	|		ПО ЗадачиЗвонокЛояльности.Телефон = НеПерезваниватьСрезПоследних.Телефон
	|ГДЕ
	|	ЕСТЬNULL(Продажи.Объект, """") = &Автомобиль";
	Запрос.УстановитьПараметр("Автомобиль", Автомобиль);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	ЗаполнитьЗначенияСвойств(ЭтотОбъект.Ремонты_ПодобныеЗадачи, РезультатЗапроса);
	
КонецФункции

Функция ЗагрузиСоответствиеТочекПродажПодразделениям() Экспорт
	
		Запрос = Новый Запрос();
		Запрос.Текст = 
		"ВЫБРАТЬ
		|	ТочкиПродажВподразделения.Точка КАК Точка,
		|	ТочкиПродажВподразделения.Подразделение КАК Подразделение,
		|	ТочкиПродажВподразделения.ДопРеквизитАдресации КАК ДопРеквизитАдресации
		|ИЗ
		|	РегистрСведений.ТочкиПродажВподразделения КАК ТочкиПродажВподразделения";
		РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
		Выборка = РезультатЗапроса.Выбрать();
		Пока Выборка.Следующий() Цикл
			Новая = ЭтотОбъект.ТочкиПродажиВПодразделения.Добавить();
			Новая.ТочкаПродажи  		= Выборка.Точка;
			Новая.Подразделение 		= Выборка.Подразделение;
			Новая.ДопРеквизитАдресации  = Выборка.ДопРеквизитАдресации;
		КонецЦикла;
		
КонецФункции