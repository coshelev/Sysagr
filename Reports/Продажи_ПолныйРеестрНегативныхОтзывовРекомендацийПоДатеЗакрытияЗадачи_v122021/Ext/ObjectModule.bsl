﻿
Функция УстановитьНастройки(ОтборПоТочкам = Истина) Экспорт   
	
	//Получи перечень точек оформления, фигуировавших в течении последнего месяца
	//---------------------------------------------------------------------------	
	Запрос = Новый Запрос("ВЫБРАТЬ РАЗЛИЧНЫЕ Точка ИЗ РегистрСведений.Продажи ГДЕ Вид = ""Продажа авто"" И Дата МЕЖДУ ДОБАВИТЬКДАТЕ(&ДатаДок, МЕСЯЦ, -3) И &ДатаДок УПОРЯДОЧИТЬ ПО Точка");
	Запрос.УстановитьПараметр("ДатаДок", ТекущаяДата());	
	Рез = Запрос.Выполнить();
	Если Рез.Пустой() Тогда
		Возврат ""
	КонецЕсли;

	ДоступныеТочки = Новый Массив();    
	ДоступныеТочки = Рез.Выгрузить().ВыгрузитьКолонку(0);
	
	Если Не ПараметрыСеанса.РольДоступнаАдминистратор Тогда 
		ДоступныеТочки.Очистить();
		
		//Определи доступные точки для отбора
		//-----------------------------------
		Запрос = Новый Запрос();
		Запрос.Текст = 
		"ВЫБРАТЬ РАЗЛИЧНЫЕ
		|	ВЫРАЗИТЬ(Рег.Точка КАК СТРОКА(32)) КАК Точка
		|ИЗ
		|	Справочник.Предприятие КАК Предприятие
		|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ РегистрСведений.ТочкиПродажВподразделения КАК Рег
		|		ПО Предприятие.Ссылка = Рег.Подразделение
		|ГДЕ
		|	Предприятие.Ссылка В ИЕРАРХИИ
		|			(ВЫБРАТЬ РАЗЛИЧНЫЕ
		|				ПользователиПодразделения.Подразделение
		|			ИЗ
		|				Справочник.Пользователи.Подразделения КАК ПользователиПодразделения
		|			ГДЕ
		|				ПользователиПодразделения.Ссылка = &Ссылка)";
		Запрос.УстановитьПараметр("Ссылка", ПараметрыСеанса.ТекущийПользователь);
		Рзт = Запрос.Выполнить();
		Если Не Рзт.Пустой() Тогда
			ДоступныеТочки = Рзт.Выгрузить().ВыгрузитьКолонку(0);
		КонецЕсли;
	КонецЕсли;
	
	Выб = Рез.Выбрать();
	Пока Выб.Следующий() Цикл
		Новая = ТочкиОформления.Добавить();
		Новая.ТочкаОформления	= Выб.Точка;
		Новая.Отбор				= ?(ДоступныеТочки.Найти(Выб.Точка)=Неопределено, Ложь, Истина);
	КонецЦикла;
	
	Запрос = Новый Запрос("ВЫБРАТЬ РАЗЛИЧНЫЕ ХарактеристикаОбъекта  ИЗ РегистрСведений.Продажи ГДЕ Вид = ""Продажа авто"" И Дата МЕЖДУ ДОБАВИТЬКДАТЕ(&ДатаДок, МЕСЯЦ, -3) И &ДатаДок УПОРЯДОЧИТЬ ПО ХарактеристикаОбъекта");
	Запрос.УстановитьПараметр("ДатаДок", ТекущаяДата());
	Рез = Запрос.Выполнить();
	Если Рез.Пустой() Тогда
		Возврат ""
	КонецЕсли;
	
	Выб = Рез.Выбрать();
	Пока Выб.Следующий() Цикл
		Новая = ВидыРемонта.Добавить();
		Новая.ВидРемонта	= Выб.ХарактеристикаОбъекта;
		Новая.Отбор			= Истина;
	КонецЦикла;

КонецФункции

Функция СформироватьОтчет(ТаблДок, СигнатураПродажи = "") Экспорт
	//Параметр СигнатураПродажи заполнен когда отчет строится из консоли негативных отзывов
	
	ТаблДок.Очистить();
	
	Запрос = Новый Запрос();
	Запрос.Текст =  
	"ВЫБРАТЬ
	|	ЗадачиЗвонокЛояльности.СигнатураПродажи КАК СигнатураЗадачи,
	|	ЗадачиЗвонокЛояльности.Телефон КАК Телефон,
	|	Продажи.Точка КАК Точка,
	|	Продажи.Номер КАК Номер,
	|	Продажи.Дата КАК Дата,
	|	Продажи.КонтактноеЛицо КАК КонтактноеЛицо,
	|	Продажи.Сотрудник КАК Сотрудник,
	|	Продажи.Объект КАК Автомобиль
	|ПОМЕСТИТЬ ВТ01_Задачи
	|ИЗ
	|	РегистрСведений.ЗадачиЗвонокЛояльности КАК ЗадачиЗвонокЛояльности
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ РегистрСведений.Продажи КАК Продажи
	|		ПО ЗадачиЗвонокЛояльности.СигнатураПродажи = Продажи.Сигнатура
	|ГДЕ
	|	ЗадачиЗвонокЛояльности.ДатаЗакрытия МЕЖДУ НАЧАЛОПЕРИОДА(&ДатаНачалаПериодаЗакрытияЗадач, ДЕНЬ) И КОНЕЦПЕРИОДА(&ДатаКонцаПериодаЗакрытияЗадач, ДЕНЬ)
	|	И ЗадачиЗвонокЛояльности.Тип = ЗНАЧЕНИЕ(Перечисление.ТипЗадачи.ЛояльностьПродажАвто)
	|	И Продажи.Точка В(&ТочкиОформления)
	|	И ЗадачиЗвонокЛояльности.ПричинаЗакрытия = """"
	|	И 2 = 2
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ РАЗЛИЧНЫЕ
	|	МАКСИМУМ(Анкеты.Период) КАК Период,
	|	Анкеты.Телефон КАК Телефон,
	|	Анкеты.Вопрос КАК Вопрос,
	|	Анкеты.Номер КАК Номер,
	|	ВТ01.СигнатураЗадачи КАК СигнатураЗадачи
	|ПОМЕСТИТЬ ВТ001_СрезПоследнихПоСигнатуре
	|ИЗ
	|	РегистрСведений.АнкетыРасширенные КАК Анкеты
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ01_Задачи КАК ВТ01
	|		ПО Анкеты.СигнатураЗадачQ = ВТ01.СигнатураЗадачи
	|ГДЕ
	|	Анкеты.Период <= КОНЕЦПЕРИОДА(&ДатаКонцаПериодаЗакрытияЗадач, ДЕНЬ)
	|
	|СГРУППИРОВАТЬ ПО
	|	Анкеты.Телефон,
	|	Анкеты.Вопрос,
	|	Анкеты.Номер,
	|	ВТ01.СигнатураЗадачи
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	АнкетыРасширенные.СигнатураЗадачQ КАК СигнатураЗадачи,
	|	АнкетыРасширенные.Вопрос КАК Вопрос,
	|	АнкетыРасширенные.Ответ КАК Ответ,
	|	АнкетыРасширенные.ОтветКомментарий.ПолнаяСтрока КАК ОтветКомментарий,
	|	ВТ01.Телефон КАК Телефон,
	|	ВТ01.Точка КАК Точка,
	|	ВТ01.Номер КАК Номер,
	|	ВТ01.Дата КАК Дата,
	|	ВТ01.КонтактноеЛицо КАК КонтактноеЛицо,
	|	ВТ01.Сотрудник КАК Сотрудник,
	|	ВТ01.Автомобиль КАК Автомобиль
	|ПОМЕСТИТЬ ВТ02_АнкетыЗадачБезФильтраПоВопросам
	|ИЗ
	|	РегистрСведений.АнкетыРасширенные КАК АнкетыРасширенные
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ001_СрезПоследнихПоСигнатуре КАК ВТ001
	|		ПО АнкетыРасширенные.Период = ВТ001.Период
	|			И АнкетыРасширенные.Телефон = ВТ001.Телефон
	|			И АнкетыРасширенные.Вопрос = ВТ001.Вопрос
	|			И АнкетыРасширенные.Номер = ВТ001.Номер
	|			И АнкетыРасширенные.СигнатураЗадачQ = ВТ001.СигнатураЗадачи
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ01_Задачи КАК ВТ01
	|		ПО (ВТ01.СигнатураЗадачи = АнкетыРасширенные.СигнатураЗадачQ)
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ РАЗЛИЧНЫЕ
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.СигнатураЗадачи КАК СигнатураЗадачи
	|ПОМЕСТИТЬ ВТ03_ОтборПоВопросам
	|ИЗ
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам КАК ВТ02_АнкетыЗадачБезФильтраПоВопросам
	|ГДЕ
	|	(ВТ02_АнкетыЗадачБезФильтраПоВопросам.Вопрос В (&Вопрос1)
	|				И ВТ02_АнкетыЗадачБезФильтраПоВопросам.Ответ В (&Ответ1, &Ответ2, &Ответ3)
	|			ИЛИ ВТ02_АнкетыЗадачБезФильтраПоВопросам.Вопрос В (&Вопрос2)
	|				И ВТ02_АнкетыЗадачБезФильтраПоВопросам.Ответ В (&Ответ1, &Ответ2, &Ответ3)
	|			ИЛИ ВТ02_АнкетыЗадачБезФильтраПоВопросам.Вопрос В (&Вопрос3)
	|				И ВТ02_АнкетыЗадачБезФильтраПоВопросам.Ответ В (&Ответ1, &Ответ2, &Ответ3)
	|			ИЛИ ВТ02_АнкетыЗадачБезФильтраПоВопросам.Вопрос В (&Вопрос4)
	|				И ВТ02_АнкетыЗадачБезФильтраПоВопросам.Ответ В (&Ответ1, &Ответ2, &Ответ3))
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.Точка КАК Точка,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.Номер КАК Номер,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.Дата КАК Дата,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.Сотрудник КАК Сотрудник,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.Автомобиль КАК Автомобиль,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.Телефон КАК Телефон,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.КонтактноеЛицо КАК КонтактноеЛицо,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.СигнатураЗадачи КАК СигнатураЗадачи,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.Вопрос КАК Вопрос,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.Ответ КАК Ответ,
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам.ОтветКомментарий КАК ОтветКомментарий
	|ИЗ
	|	ВТ02_АнкетыЗадачБезФильтраПоВопросам КАК ВТ02_АнкетыЗадачБезФильтраПоВопросам
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ03_ОтборПоВопросам КАК ВТ03_Отбор
	|		ПО ВТ02_АнкетыЗадачБезФильтраПоВопросам.СигнатураЗадачи = ВТ03_Отбор.СигнатураЗадачи
	|ИТОГИ ПО
	|	Точка,
	|	Номер,
	|	Дата,
	|	Сотрудник,
	|	Автомобиль,
	|	Телефон,
	|	КонтактноеЛицо,
	|	СигнатураЗадачи
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	Пакеты.Сигнатура КАК СигнатураМастерПродажи,
	|	Пакеты.Продажа КАК СигнатураПодчиненнойПродажи,
	|	Продажи.Номер КАК Номер,
	|	Продажи.Дата КАК Дата,
	|	Продажи.КонтактноеЛицо КАК КонтактноеЛицо,
	|	Продажи.Сотрудник КАК Сотрудник
	|ИЗ
	|	РегистрСведений.ЗадачиЛояльностиПакеты КАК Пакеты
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ03_ОтборПоВопросам КАК ВТ03_Отбор
	|		ПО Пакеты.Сигнатура = ВТ03_Отбор.СигнатураЗадачи
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ РегистрСведений.Продажи КАК Продажи
	|		ПО Пакеты.Продажа = Продажи.Сигнатура";
	
	
	СписокВыбранныхТочекОформления = Новый Массив(); 
	Для Каждого Стр из ЭтотОбъект.ТочкиОформления Цикл
		Если Стр.Отбор = Истина Тогда
			СписокВыбранныхТочекОформления.Добавить(Стр.ТочкаОформления);
		КонецЕсли;
	КонецЦикла;
	
	//Если задана сигнатура продажи, значит это вызов из консоли, все точки делаем активными
	Если ЗначениеЗаполнено(СигнатураПродажи) Тогда
		СписокВыбранныхТочекОформления.Очистить();
		Для Каждого Стр из ЭтотОбъект.ТочкиОформления Цикл
			СписокВыбранныхТочекОформления.Добавить(Стр.ТочкаОформления);
		КонецЦикла;
	КонецЕсли;
	
	Запрос.УстановитьПараметр("ТочкиОформления", СписокВыбранныхТочекОформления);	
	Запрос.УстановитьПараметр("ДатаНачалаПериодаЗакрытияЗадач", 	ЭтотОбъект.ДатаНачалаПериодаЗакрытияЗадач);
	Запрос.УстановитьПараметр("ДатаКонцаПериодаЗакрытияЗадач", 		ЭтотОбъект.ДатаКонцаПериодаЗакрытияЗадач);
	Запрос.УстановитьПараметр("Вопрос1", 							Анкета._1йБазовыйВопросЛояльности());
	Запрос.УстановитьПараметр("Вопрос2",							Анкета._2йБазовыйВопросЛояльности());
	Запрос.УстановитьПараметр("Вопрос3", 							Анкета._3йБазовыйВопросЛояльности());
	Запрос.УстановитьПараметр("Вопрос4",							Анкета._4йБазовыйВопросЛояльности());
	Запрос.УстановитьПараметр("Ответ1", 							Анкета._1());
	Запрос.УстановитьПараметр("Ответ2", 							Анкета._2());
	Запрос.УстановитьПараметр("Ответ3", 							Анкета._3());
	
	//Если отчет вызван из консоли негативных отзывов
	//------------------------------------------------
	Если ЗначениеЗаполнено(СигнатураПродажи) Тогда
		Запрос.Текст = СтрЗаменить(Запрос.Текст, "2 = 2", "Продажи.Сигнатура = &СигнатураПродажи");
		
		ТекДата = ТекущаяДата();
		Запрос.УстановитьПараметр("ДатаНачалаПериодаЗакрытияЗадач", 	ДобавитьМесяц(ТекДата, -6));
		Запрос.УстановитьПараметр("ДатаКонцаПериодаЗакрытияЗадач", 		ТекДата);
		Запрос.УстановитьПараметр("СигнатураПродажи",					СигнатураПродажи);
	КонецЕсли;
	
	ПакетРезультатов = Запрос.ВыполнитьПакет();
	Рез = ПакетРезультатов[4];
	Если Рез.Пустой() Тогда
		Возврат ""; 
	КонецЕсли;
	
	ЗаказНарядыВПакетах = ПакетРезультатов[5].Выгрузить();
	
	
	Макет = ЭтотОбъект.ПолучитьМакет("МакетОтчета");
	
	ВыбТочка = Рез.Выбрать(ОбходРезультатаЗапроса.ПоГруппировкам);
	Пока ВыбТочка.Следующий() Цикл
		ВыбНомер = ВыбТочка.Выбрать(ОбходРезультатаЗапроса.ПоГруппировкам);
		
		Пока ВыбНомер.Следующий() Цикл
			ВыбДата = ВыбНомер.Выбрать(ОбходРезультатаЗапроса.ПоГруппировкам);
			
			Пока ВыбДата.Следующий() Цикл
				ВыбСотрудник = ВыбДата.Выбрать(ОбходРезультатаЗапроса.ПоГруппировкам);
				
				Пока ВыбСотрудник.Следующий() Цикл
					ВыбАвтомобиль = ВыбСотрудник.Выбрать(ОбходРезультатаЗапроса.ПоГруппировкам);
					
					Пока ВыбАвтомобиль.Следующий() Цикл
						ВыбТелефон = ВыбАвтомобиль.Выбрать(ОбходРезультатаЗапроса.ПоГруппировкам);
						
						Пока ВыбТелефон.Следующий() Цикл
							ВыбКонтакт = ВыбТелефон.Выбрать(ОбходРезультатаЗапроса.ПоГруппировкам);
							
							Пока ВыбКонтакт.Следующий() Цикл
								
								ВыбСигнатура = ВыбКонтакт.Выбрать(ОбходРезультатаЗапроса.ПоГруппировкам);
								
								Пока ВыбСигнатура.Следующий() Цикл
									ОблШапка = Макет.ПолучитьОбласть("Шапка|Кол1");
									ОблШапка.Вывести(ОблШапка);

									ОблШапка = Макет.ПолучитьОбласть("Шапка|ОсновныеКолонки");
									ОблШапка.Параметры.ПечТочкаОформления = ВыбКонтакт.Точка;
									
									ЗаказНаряды = ВыбКонтакт.Номер+" от "+Формат(ВыбКонтакт.Дата, "ДФ=dd.MM.yyyy");
									Сотрудники  = ВыбКонтакт.Сотрудник;
									
									// Вывод списка заказ-нарядов и сотрудников
									//------------------------------------------
									Отб = Новый Структура();
									Отб.Вставить("СигнатураМастерПродажи", ВыбСигнатура.СигнатураЗадачи);
									Найденные = ЗаказНарядыВПакетах.НайтиСтроки(Отб);
									Для Каждого Стр Из Найденные Цикл
										ЗаказНаряды = ЗаказНаряды+";"+Стр.Номер+" от "+	Формат(Стр.Дата, "ДФ=dd.MM.yyyy");
										
										Если СтрНайти(Сотрудники, Стр.Сотрудник)= 0 Тогда
											Сотрудники = Сотрудники + "; "+Стр.Сотрудник;
										КонецЕсли;
									КонецЦикла;
									ОблШапка.Параметры.ПечНомераДатыЗаказНарядов 	= ЗаказНаряды;
									ОблШапка.Параметры.ПечФИОСотрудников 			= Сотрудники;
									
									
									ОблШапка.Параметры.ПечАвтомобиль				= ВыбКонтакт.Автомобиль;
									ОблШапка.Параметры.ПечТелНомерКонтактногоЛица	= ВыбКонтакт.Телефон;
									ОблШапка.Параметры.ПечФИОКонтактногоЛица		= ВыбКонтакт.КонтактноеЛицо;
									
									ТаблДок.Вывести(ОблШапка);
									
									ВыбДетальные = ВыбСигнатура.Выбрать();
									Пока ВыбДетальные.Следующий() Цикл
										ОблСтр = Макет.ПолучитьОбласть("Строка|Кол1");
										ОблСтр.Вывести(ОблСтр);

										ОблСтр = Макет.ПолучитьОбласть("Строка|ОсновныеКолонки");
										ОблСтр.Параметры.ПечВопрос 				= ВыбДетальные.Вопрос;
										ОблСтр.Параметры.ПечОтвет				= ВыбДетальные.Ответ;
										ОблСтр.Параметры.ПечОтветКомментарий 	= ВыбДетальные.ОтветКомментарий;  
										
										ОблЯчеек = ТаблДок.Вывести(ОблСтр);
										
										//// Условное форматирование
										////------------------------
										//Доступно = ВыбДетальные.Ответ = ЭтотОбъект.ИдОтвет_Нет;
										//Доступно = Доступно ИЛИ ВыбДетальные.Ответ = ЭтотОбъект.ИдОтвет_1;
										//Доступно = Доступно ИЛИ ВыбДетальные.Ответ = ЭтотОбъект.ИдОтвет_2;
										//Доступно = Доступно ИЛИ ВыбДетальные.Ответ = ЭтотОбъект.ИдОтвет_3;
										//Доступно = Доступно ИЛИ ВыбДетальные.Ответ = ЭтотОбъект.ИдОтвет_4;
										//Если Доступно Тогда
										//		ОблЯчеек.ЦветФона = webцвета.БледноБирюзовый;	
										//КонецЕсли;

									КонецЦикла;
								КонецЦикла;
								
							КонецЦикла;
						КонецЦикла;
					КонецЦикла;
				КонецЦикла;
			КонецЦикла;
		КонецЦикла;
	КонецЦикла;
	
	
КонецФункции